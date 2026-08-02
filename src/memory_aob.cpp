#include "memory_internal.hpp"

namespace hdl {

int HexNibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool ParseAobPattern(const char* pattern, std::vector<uint8_t>& bytes, std::vector<uint8_t>& mask) {
    bytes.clear();
    mask.clear();
    if (!pattern) {
        return false;
    }

    const char* p = pattern;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            ++p;
        }
        if (!*p) {
            break;
        }
        if (*p == '?') {
            bytes.push_back(0);
            mask.push_back(0);
            ++p;
            if (*p == '?') {
                ++p;
            }
            continue;
        }
        const int hi = HexNibble(*p++);
        if (hi < 0) {
            return false;
        }
        while (*p == ' ' || *p == '\t') {
            ++p;
        }
        if (!*p) {
            return false;
        }
        const int lo = HexNibble(*p++);
        if (lo < 0) {
            return false;
        }
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
        mask.push_back(0xFF);
    }
    return !bytes.empty() && bytes.size() == mask.size();
}

HdlStatus SearchMemory(uint64_t start, uint64_t size, const char* pattern, uint64_t* out_hits,
                       uint32_t* inout_hit_count, volatile int* cancel) {
    if (!pattern || !inout_hit_count) {
        return HDL_E_INVALID_ARG;
    }

    HdlSearchSession* session = nullptr;
    HdlStatus st = SearchCreate(&session);
    if (st != HDL_OK) {
        return st;
    }

    HdlSearchDesc desc{};
    desc.start = start;
    desc.size = size;
    desc.value_type = HDL_VALUE_BYTES;
    desc.cmp = HDL_CMP_EXACT;
    desc.alignment = 1;
    desc.max_results = *inout_hit_count;
    desc.value = pattern;
    desc.value_size = 0;

    st = SearchFirst(session, &desc, cancel);
    if (st == HDL_OK || st == HDL_E_CANCELLED) {
        uint32_t count = *inout_hit_count;
        const HdlStatus gst = SearchGetHits(session, out_hits, &count);
        if (gst == HDL_E_BUFFER_SMALL && (!out_hits || *inout_hit_count == 0)) {
            *inout_hit_count = count;
            SearchClose(session);
            return HDL_E_BUFFER_SMALL;
        }
        *inout_hit_count = count;
    }
    SearchClose(session);
    return st;
}

} // namespace hdl
