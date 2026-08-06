#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "memory.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace hdl::ipc {
namespace {

constexpr size_t kSearchChunk = 4096;

template <typename Response> class SearchHitStreamer {
  public:
    explicit SearchHitStreamer(rpc::ServerWriter<Response>* writer) : writer_(writer) {
        buffer_.reserve(kSearchChunk);
    }

    static HdlStatus OnHitThunk(uint64_t address, void* user) {
        return static_cast<SearchHitStreamer*>(user)->OnHit(address);
    }

    HdlStatus OnHit(uint64_t address) {
        if (failed_) {
            return HDL_E_CANCELLED;
        }
        buffer_.push_back(address);
        return buffer_.size() == kSearchChunk ? Flush(false) : HDL_OK;
    }

    rpc::Status Finish(HdlStatus status) {
        if (failed_) {
            return rpc::Status::FromHdl(HDL_E_CANCELLED);
        }
        if (status == HDL_OK || !buffer_.empty()) {
            const HdlStatus write_status = Flush(true);
            if (write_status != HDL_OK) {
                return rpc::Status::FromHdl(write_status);
            }
        }
        return rpc::Status::FromHdl(status);
    }

  private:
    HdlStatus Flush(bool final_batch) {
        Response response;
        for (uint64_t address : buffer_) {
            response.add_addresses(address);
        }
        emitted_ += buffer_.size();
        if (final_batch) {
            response.set_total(emitted_);
        }
        buffer_.clear();
        if (!writer_->Write(response)) {
            failed_ = true;
            return HDL_E_CANCELLED;
        }
        return HDL_OK;
    }

    rpc::ServerWriter<Response>* writer_ = nullptr;
    std::vector<uint64_t> buffer_;
    uint64_t emitted_ = 0;
    bool failed_ = false;
};

template <typename Response>
rpc::Status WriteStoredHits(HdlStatus status, const std::vector<uint64_t>& hits, uint64_t total,
                            rpc::ServerWriter<Response>& writer) {
    if (status != HDL_OK) {
        return rpc::Status::FromHdl(status);
    }
    if (hits.empty()) {
        Response response;
        response.set_total(total);
        return writer.Write(response) ? rpc::Status::Ok() : rpc::Status::FromHdl(HDL_E_CANCELLED);
    }
    for (size_t offset = 0; offset < hits.size(); offset += kSearchChunk) {
        Response response;
        const size_t end = (std::min)(hits.size(), offset + kSearchChunk);
        for (size_t index = offset; index < end; ++index) {
            response.add_addresses(hits[index]);
        }
        if (end == hits.size()) {
            response.set_total(total);
        }
        if (!writer.Write(response)) {
            return rpc::Status::FromHdl(HDL_E_CANCELLED);
        }
    }
    return rpc::Status::Ok();
}

bool BuildSearchDesc(const rpc::v1::SearchScope& scope, const rpc::v1::SearchValue& value,
                     rpc::v1::SearchComparison comparison, rpc::v1::SearchAlignment alignment,
                     uint32_t max_results, SearchValueStorage* storage, std::wstring* module,
                     HdlSearchDesc* desc) {
    const int comparison_value = static_cast<int>(comparison);
    const int alignment_value = static_cast<int>(alignment);
    if (comparison_value < rpc::v1::SEARCH_COMPARISON_EXACT ||
        comparison_value > rpc::v1::SEARCH_COMPARISON_LESS ||
        alignment_value < rpc::v1::SEARCH_ALIGNMENT_NATURAL ||
        alignment_value > rpc::v1::SEARCH_ALIGNMENT_BYTE || !FromProto(value, storage) ||
        !Utf8ToWide(scope.module(), module)) {
        return false;
    }
    *desc = {};
    desc->start = scope.start();
    desc->size = scope.size();
    desc->value_type = storage->type;
    desc->cmp = static_cast<int32_t>(comparison);
    desc->alignment = static_cast<uint32_t>(alignment);
    desc->max_results = max_results;
    desc->value = storage->data();
    desc->value_size = storage->size();
    desc->flags = scope.flags();
    desc->module_or_null = module->empty() ? nullptr : module->c_str();
    return true;
}

} // namespace

rpc::Status HandleSearch_SearchMemory(rpc::CallContext&,
                                      const rpc::v1::SearchMemoryRequest& request,
                                      rpc::ServerWriter<rpc::v1::SearchMemoryResponse>& writer) {
    if (request.aob_pattern().find('\0') != std::string::npos) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    SearchHitStreamer<rpc::v1::SearchMemoryResponse> stream(&writer);
    HdlSearchSession* session = nullptr;
    HdlStatus status = SearchCreate(&session);
    if (status == HDL_OK) {
        SearchSetRetainHits(session, false);
        SearchSetHitHandler(session, &SearchHitStreamer<rpc::v1::SearchMemoryResponse>::OnHitThunk,
                            &stream);
        HdlSearchDesc desc{};
        desc.start = request.scope().start();
        desc.size = request.scope().size();
        desc.value_type = HDL_VALUE_BYTES;
        desc.cmp = HDL_CMP_EXACT;
        desc.alignment = 1;
        desc.max_results = request.max_hits();
        desc.value = request.aob_pattern().c_str();
        desc.flags = request.scope().flags();
        desc.module_or_null = module.empty() ? nullptr : module.c_str();
        status = SearchFirst(session, &desc, MakeToken(nullptr, CurrentRequestJob()));
        SearchSetHitHandler(session, nullptr, nullptr);
        SearchClose(session);
    }
    return stream.Finish(status);
}

rpc::Status HandleSearch_SearchCreate(rpc::CallContext&, const rpc::v1::Empty&,
                                      rpc::v1::SearchCreateResponse* response) {
    HdlSearchSession* session = nullptr;
    const HdlStatus status = SearchCreate(&session);
    if (status == HDL_OK) {
        response->set_session_id(AllocSearchSession(session));
    }
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleSearch_SearchClose(rpc::CallContext&, const rpc::v1::SearchCloseRequest& request,
                                     rpc::v1::Empty*) {
    auto holder = TakeSearchSession(request.session_id());
    if (!holder) {
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    }
    std::lock_guard<std::mutex> lock(holder->mu);
    if (holder->session) {
        SearchClose(holder->session);
        holder->session = nullptr;
    }
    return rpc::Status::Ok();
}

rpc::Status HandleSearch_SearchReset(rpc::CallContext&, const rpc::v1::SearchResetRequest& request,
                                     rpc::v1::Empty*) {
    auto holder = FindSession(request.session_id());
    if (!holder) {
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    }
    std::lock_guard<std::mutex> lock(holder->mu);
    if (!holder->session) {
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    }
    SearchReset(holder->session);
    return rpc::Status::Ok();
}

rpc::Status HandleSearch_SearchFirst(rpc::CallContext&, const rpc::v1::SearchFirstRequest& request,
                                     rpc::ServerWriter<rpc::v1::SearchFirstResponse>& writer) {
    SearchValueStorage storage;
    std::wstring module;
    HdlSearchDesc desc{};
    if (!request.has_value() ||
        !BuildSearchDesc(request.scope(), request.value(), request.comparison(),
                         request.alignment(), request.max_results(), &storage, &module, &desc)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    auto holder = FindSession(request.session_id());
    if (!holder) {
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    }
    SearchHitStreamer<rpc::v1::SearchFirstResponse> stream(&writer);
    HdlStatus status = HDL_E_NOT_FOUND;
    {
        std::lock_guard<std::mutex> lock(holder->mu);
        if (!holder->session) {
            return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
        }
        SearchSetRetainHits(holder->session, true);
        SearchSetHitHandler(holder->session,
                            &SearchHitStreamer<rpc::v1::SearchFirstResponse>::OnHitThunk, &stream);
        status = SearchFirst(holder->session, &desc, MakeToken(nullptr, CurrentRequestJob()));
        SearchSetHitHandler(holder->session, nullptr, nullptr);
    }
    return stream.Finish(status);
}

rpc::Status HandleSearch_SearchNext(rpc::CallContext&, const rpc::v1::SearchNextRequest& request,
                                    rpc::v1::SearchNextResponse* response) {
    const int comparison = static_cast<int>(request.comparison());
    if (comparison < rpc::v1::SEARCH_COMPARISON_EXACT ||
        comparison > rpc::v1::SEARCH_COMPARISON_LESS) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    SearchValueStorage storage;
    const void* value = nullptr;
    size_t value_size = 0;
    if (request.has_value()) {
        if (!FromProto(request.value(), &storage)) {
            return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
        }
        value = storage.data();
        value_size = storage.size();
    }
    auto holder = FindSession(request.session_id());
    if (!holder) {
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    }
    uint32_t count = 0;
    HdlStatus status = HDL_E_NOT_FOUND;
    {
        std::lock_guard<std::mutex> lock(holder->mu);
        if (!holder->session) {
            return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
        }
        status = SearchNext(holder->session, comparison, value, value_size,
                            MakeToken(nullptr, CurrentRequestJob()));
        SearchGetCount(holder->session, &count);
    }
    response->set_remaining_count(count);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleSearch_SearchGetHits(rpc::CallContext&,
                                       const rpc::v1::SearchGetHitsRequest& request,
                                       rpc::ServerWriter<rpc::v1::SearchGetHitsResponse>& writer) {
    auto holder = FindSession(request.session_id());
    if (!holder) {
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    }
    uint32_t total = 0;
    std::vector<uint64_t> hits;
    HdlStatus status = HDL_OK;
    {
        std::lock_guard<std::mutex> lock(holder->mu);
        if (!holder->session) {
            return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
        }
        SearchGetCount(holder->session, &total);
        hits.resize(total);
        uint32_t count = total;
        status = total ? SearchGetHits(holder->session, hits.data(), &count) : HDL_OK;
        hits.resize(status == HDL_OK ? count : 0);
    }
    if (request.max_hits() && hits.size() > request.max_hits()) {
        hits.resize(request.max_hits());
    }
    return WriteStoredHits(status, hits, total, writer);
}

} // namespace hdl::ipc
