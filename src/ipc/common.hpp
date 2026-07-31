#pragma once

#include "framing.hpp"
#include "jobs.hpp"
#include "protocol.hpp"

#include "hdllib/hdllib.h"

#include <cstdint>
#include <memory>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace ipc {

bool WriteFrame(HANDLE pipe, const std::vector<uint8_t>& resp);

// Optional trailer: job_id (u64), timeout_ms (u32), flags (u32). Missing fields default to 0.
void TakeOptionalJobTimeoutFlags(proto::Reader& r, uint64_t* job_id, uint32_t* timeout_ms,
                                 uint32_t* flags);

std::shared_ptr<Job> BindJob(uint64_t job_id, uint32_t timeout_ms);

HdlSearchSession* FindSession(uint64_t id);
HdlDiscoverSession* FindDiscover(uint64_t id);

uint64_t AllocSearchSession(HdlSearchSession* session);
bool TakeSearchSession(uint64_t id, HdlSearchSession** out);
void CloseAllSessions();

uint64_t AllocDiscoverSession(HdlDiscoverSession* session);
bool TakeDiscoverSession(uint64_t id, HdlDiscoverSession** out);
void CloseAllDiscoverSessions();

// Chunked reply: status, flags(MORE), total, offset, count, items[count].
// `stream_count` items are written; `total` is the reported collection size (may be >= stream_count).
template <typename T>
bool WriteStreamed(HANDLE pipe, HdlStatus st, const T* items, uint32_t total, uint32_t stream_count,
                   uint32_t chunk) {
    using namespace proto;
    if (stream_count == 0 || !items) {
        std::vector<uint8_t> frame;
        AppendPod(frame, static_cast<int32_t>(st));
        AppendPod(frame, static_cast<uint32_t>(0));
        AppendPod(frame, total);
        AppendPod(frame, 0u);
        AppendPod(frame, 0u);
        return WriteFrame(pipe, frame);
    }
    for (uint32_t off = 0; off < stream_count; off += chunk) {
        const uint32_t n = (off + chunk <= stream_count) ? chunk : (stream_count - off);
        const bool more = (off + n) < stream_count;
        std::vector<uint8_t> frame;
        AppendPod(frame, static_cast<int32_t>(st));
        AppendPod(frame, static_cast<uint32_t>(more ? HDL_IPC_MORE : 0));
        AppendPod(frame, total);
        AppendPod(frame, off);
        AppendPod(frame, n);
        AppendBytes(frame, items + off, n * sizeof(T));
        if (!WriteFrame(pipe, frame)) {
            return false;
        }
    }
    return true;
}

template <typename T>
bool WriteStreamed(HANDLE pipe, HdlStatus st, const T* items, uint32_t total, uint32_t chunk) {
    return WriteStreamed(pipe, st, items, total, total, chunk);
}

/* Bounded hit buffer for search streaming. Flush (WriteFile) blocks until the client
 * drains the pipe — that is the scan backpressure when the buffer is full.
 * Frame: status, flags(MORE), total (0 until final), count, u64[count]. */
constexpr uint32_t kSearchStreamCap = 4096;

inline bool WriteSearchStreamError(HANDLE pipe, HdlStatus st) {
    using namespace proto;
    std::vector<uint8_t> frame;
    AppendPod(frame, static_cast<int32_t>(st));
    AppendPod(frame, 0u); /* flags */
    AppendPod(frame, 0u); /* total */
    AppendPod(frame, 0u); /* count */
    return WriteFrame(pipe, frame);
}

inline bool WriteSearchHitsStreamed(HANDLE pipe, HdlStatus st, const uint64_t* items,
                                   uint32_t total, uint32_t stream_count, uint32_t chunk) {
    using namespace proto;
    if (stream_count == 0 || !items) {
        return WriteSearchStreamError(pipe, st);
    }
    for (uint32_t off = 0; off < stream_count; off += chunk) {
        const uint32_t n = (off + chunk <= stream_count) ? chunk : (stream_count - off);
        const bool more = (off + n) < stream_count;
        std::vector<uint8_t> frame;
        AppendPod(frame, static_cast<int32_t>(more ? HDL_OK : st));
        AppendPod(frame, more ? static_cast<uint32_t>(HDL_IPC_MORE) : 0u);
        AppendPod(frame, more ? 0u : total);
        AppendPod(frame, n);
        AppendBytes(frame, items + off, n * sizeof(uint64_t));
        if (!WriteFrame(pipe, frame)) {
            return false;
        }
    }
    return true;
}

struct SearchHitStreamer {
    HANDLE pipe = nullptr;
    std::vector<uint64_t> buf;
    uint32_t emitted = 0;
    bool failed = false;

    explicit SearchHitStreamer(HANDLE p) : pipe(p) {
        buf.reserve(kSearchStreamCap);
    }

    static HdlStatus OnHitThunk(uint64_t address, void* user) {
        return static_cast<SearchHitStreamer*>(user)->OnHit(address);
    }

    HdlStatus OnHit(uint64_t address) {
        if (failed) {
            return HDL_E_FAILED;
        }
        buf.push_back(address);
        if (buf.size() >= kSearchStreamCap) {
            return Flush(/*more=*/true);
        }
        return HDL_OK;
    }

    HdlStatus Flush(bool more) {
        using namespace proto;
        if (failed) {
            return HDL_E_FAILED;
        }
        if (buf.empty() && more) {
            return HDL_OK;
        }
        std::vector<uint8_t> frame;
        AppendPod(frame, static_cast<int32_t>(HDL_OK));
        AppendPod(frame, more ? static_cast<uint32_t>(HDL_IPC_MORE) : 0u);
        AppendPod(frame, 0u); /* total unknown until Finish */
        AppendPod(frame, static_cast<uint32_t>(buf.size()));
        if (!buf.empty()) {
            AppendBytes(frame, buf.data(), buf.size() * sizeof(uint64_t));
        }
        if (!WriteFrame(pipe, frame)) {
            failed = true;
            return HDL_E_FAILED;
        }
        emitted += static_cast<uint32_t>(buf.size());
        buf.clear();
        return HDL_OK;
    }

    bool Finish(HdlStatus st) {
        using namespace proto;
        if (failed) {
            return false;
        }
        const uint32_t total = emitted + static_cast<uint32_t>(buf.size());
        std::vector<uint8_t> frame;
        AppendPod(frame, static_cast<int32_t>(st));
        AppendPod(frame, 0u); /* final */
        AppendPod(frame, total);
        AppendPod(frame, static_cast<uint32_t>(buf.size()));
        if (!buf.empty()) {
            AppendBytes(frame, buf.data(), buf.size() * sizeof(uint64_t));
        }
        buf.clear();
        emitted = total;
        return WriteFrame(pipe, frame);
    }
};

}  // namespace ipc
}  // namespace hdl
