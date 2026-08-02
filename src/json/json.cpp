#include "json/json.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>

namespace hdl {
namespace json {
namespace {

bool DecodeEscape(const std::string& json, size_t* p, std::string* out) {
    if (!p || !out || *p >= json.size() || json[*p] != '\\') {
        return false;
    }
    if (*p + 1 >= json.size()) {
        return false;
    }
    const char e = json[*p + 1];
    switch (e) {
    case '"':
    case '\\':
    case '/':
        out->push_back(e);
        *p += 2;
        return true;
    case 'b':
        out->push_back('\b');
        *p += 2;
        return true;
    case 'f':
        out->push_back('\f');
        *p += 2;
        return true;
    case 'n':
        out->push_back('\n');
        *p += 2;
        return true;
    case 'r':
        out->push_back('\r');
        *p += 2;
        return true;
    case 't':
        out->push_back('\t');
        *p += 2;
        return true;
    case 'u': {
        if (*p + 5 >= json.size()) {
            return false;
        }
        unsigned code = 0;
        for (int i = 0; i < 4; ++i) {
            const char h = json[*p + 2 + i];
            code <<= 4;
            if (h >= '0' && h <= '9') {
                code |= static_cast<unsigned>(h - '0');
            } else if (h >= 'a' && h <= 'f') {
                code |= static_cast<unsigned>(h - 'a' + 10);
            } else if (h >= 'A' && h <= 'F') {
                code |= static_cast<unsigned>(h - 'A' + 10);
            } else {
                return false;
            }
        }
        if (code > 0x7F) {
            /* Minimal UTF-8 for BMP ASCII-adjacent; reject non-ASCII for simplicity. */
            if (code > 0xFF) {
                return false;
            }
            out->push_back(static_cast<char>(code));
        } else {
            out->push_back(static_cast<char>(code));
        }
        *p += 6;
        return true;
    }
    default:
        return false;
    }
}

bool ParseQuotedString(const std::string& json, size_t* p, std::string* out) {
    if (!p || !out || *p >= json.size() || json[*p] != '"') {
        return false;
    }
    ++(*p);
    out->clear();
    while (*p < json.size()) {
        if (json[*p] == '\\') {
            if (!DecodeEscape(json, p, out)) {
                return false;
            }
            continue;
        }
        if (json[*p] == '"') {
            ++(*p);
            return true;
        }
        if (static_cast<unsigned char>(json[*p]) < 0x20) {
            return false; /* unescaped control */
        }
        out->push_back(json[(*p)++]);
    }
    return false; /* unterminated */
}

bool SkipWs(const std::string& json, size_t* p) {
    if (!p) {
        return false;
    }
    while (*p < json.size() &&
           (json[*p] == ' ' || json[*p] == '\t' || json[*p] == '\n' || json[*p] == '\r')) {
        ++(*p);
    }
    return true;
}

bool FindKeyColon(const std::string& json, const char* key, size_t* out_value_pos) {
    if (!key || !out_value_pos) {
        return false;
    }
    const std::string pat = std::string("\"") + key + "\"";
    size_t p = 0;
    for (;;) {
        p = json.find(pat, p);
        if (p == std::string::npos) {
            return false;
        }
        /* Require key to be a quoted token boundary (preceded by start/{/,/ws). */
        if (p > 0) {
            const char prev = json[p - 1];
            if (prev != '{' && prev != ',' && prev != ' ' && prev != '\t' && prev != '\n' &&
                prev != '\r') {
                p += pat.size();
                continue;
            }
        }
        size_t q = p + pat.size();
        SkipWs(json, &q);
        if (q >= json.size() || json[q] != ':') {
            p += pat.size();
            continue;
        }
        ++q;
        SkipWs(json, &q);
        *out_value_pos = q;
        return true;
    }
}

/* After a number token: skip whitespace, then require a structural delimiter or EOF.
 * Whitespace alone is not a complete terminator (rejects "12 junk", "12 : 3"). */
bool AfterNumberOk(const char* p) {
    if (!p) {
        return false;
    }
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        ++p;
    }
    return *p == ',' || *p == '}' || *p == ']' || *p == '\0';
}

/* Strict JSON integer (no '+', no fraction/exponent). Decimal digits only for bare tokens. */
bool ParseStrictUIntToken(const char* start, const char** end_out, unsigned long long* out) {
    if (!start || !end_out || !out) {
        return false;
    }
    if (*start == '+' || *start == '-') {
        return false;
    }
    if (*start < '0' || *start > '9') {
        return false;
    }
    /* Disallow leading zeros except a lone 0. */
    const char* p = start;
    if (*p == '0' && p[1] >= '0' && p[1] <= '9') {
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = strtoull(p, &end, 10);
    if (end == p || errno == ERANGE) {
        return false;
    }
    /* Reject fraction / exponent / trailing junk before a JSON terminator. */
    if (*end == '.' || *end == 'e' || *end == 'E' || *end == 'x' || *end == 'X') {
        return false;
    }
    if (!AfterNumberOk(end)) {
        return false;
    }
    *end_out = end;
    *out = v;
    return true;
}

bool ParseStrictIntToken(const char* start, const char** end_out, long long* out) {
    if (!start || !end_out || !out) {
        return false;
    }
    if (*start == '+') {
        return false;
    }
    bool neg = false;
    const char* p = start;
    if (*p == '-') {
        neg = true;
        ++p;
    }
    if (*p < '0' || *p > '9') {
        return false;
    }
    if (*p == '0' && p[1] >= '0' && p[1] <= '9') {
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = strtoull(p, &end, 10);
    if (end == p || errno == ERANGE) {
        return false;
    }
    if (*end == '.' || *end == 'e' || *end == 'E' || *end == 'x' || *end == 'X') {
        return false;
    }
    if (!AfterNumberOk(end)) {
        return false;
    }
    if (neg) {
        if (v >
            static_cast<unsigned long long>(-(std::numeric_limits<long long>::min() + 1)) + 1ULL) {
            return false;
        }
        *out = -static_cast<long long>(v);
    } else {
        if (v > static_cast<unsigned long long>(std::numeric_limits<long long>::max())) {
            return false;
        }
        *out = static_cast<long long>(v);
    }
    *end_out = end;
    return true;
}

bool ParseQuotedNumberU64(const std::string& s, uint64_t* out) {
    if (!out || s.empty()) {
        return false;
    }
    /* Quoted forms may use 0x... (store / CLI hex strings). */
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = strtoull(s.c_str(), &end, 0);
    if (end == s.c_str() || *end != '\0' || errno == ERANGE) {
        return false;
    }
    *out = static_cast<uint64_t>(v);
    return true;
}

bool ParseU64InPlace(const std::string& json, size_t p, uint64_t* out) {
    if (!out || p >= json.size()) {
        return false;
    }
    const char* end = nullptr;
    unsigned long long v = 0;
    if (!ParseStrictUIntToken(json.c_str() + p, &end, &v)) {
        return false;
    }
    *out = static_cast<uint64_t>(v);
    return true;
}

bool FindMatchingBracket(const std::string& json, size_t open, char open_ch, char close_ch,
                         size_t* out_close) {
    if (!out_close || open >= json.size() || json[open] != open_ch) {
        return false;
    }
    int depth = 0;
    bool in_str = false;
    for (size_t i = open; i < json.size(); ++i) {
        const char c = json[i];
        if (in_str) {
            if (c == '\\') {
                if (i + 1 < json.size()) {
                    ++i;
                }
                continue;
            }
            if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
            continue;
        }
        if (c == open_ch) {
            ++depth;
        } else if (c == close_ch) {
            --depth;
            if (depth == 0) {
                *out_close = i;
                return true;
            }
        }
    }
    return false;
}

} // namespace

void EscapeAppend(std::string* out, const char* s, size_t n) {
    if (!out || (!s && n)) {
        return;
    }
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        switch (c) {
        case '"':
            out->append("\\\"");
            break;
        case '\\':
            out->append("\\\\");
            break;
        case '\b':
            out->append("\\b");
            break;
        case '\f':
            out->append("\\f");
            break;
        case '\n':
            out->append("\\n");
            break;
        case '\r':
            out->append("\\r");
            break;
        case '\t':
            out->append("\\t");
            break;
        default:
            if (c < 0x20) {
                char tmp[8];
                snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                out->append(tmp);
            } else {
                out->push_back(static_cast<char>(c));
            }
            break;
        }
    }
}

void EscapeAppend(std::string* out, const char* s) {
    if (!s) {
        return;
    }
    EscapeAppend(out, s, strlen(s));
}

std::string Escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    EscapeAppend(&o, s.data(), s.size());
    return o;
}

bool ExtractString(const std::string& json, const char* key, std::string* out) {
    if (!out || !key) {
        return false;
    }
    size_t p = 0;
    if (!FindKeyColon(json, key, &p)) {
        return false;
    }
    return ParseQuotedString(json, &p, out);
}

bool ExtractU64(const std::string& json, const char* key, uint64_t* out) {
    if (!out) {
        return false;
    }
    size_t p = 0;
    if (!FindKeyColon(json, key, &p)) {
        return false;
    }
    if (p < json.size() && json[p] == '"') {
        std::string s;
        if (!ParseQuotedString(json, &p, &s)) {
            return false;
        }
        return ParseQuotedNumberU64(s, out);
    }
    return ParseU64InPlace(json, p, out);
}

bool ExtractU32(const std::string& json, const char* key, uint32_t* out) {
    uint64_t v = 0;
    if (!ExtractU64(json, key, &v)) {
        return false;
    }
    if (v > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    *out = static_cast<uint32_t>(v);
    return true;
}

bool ExtractI32(const std::string& json, const char* key, int32_t* out) {
    if (!out) {
        return false;
    }
    size_t p = 0;
    if (!FindKeyColon(json, key, &p)) {
        return false;
    }
    if (p < json.size() && json[p] == '"') {
        std::string s;
        if (!ParseQuotedString(json, &p, &s) || s.empty()) {
            return false;
        }
        errno = 0;
        char* end = nullptr;
        const long long v = strtoll(s.c_str(), &end, 0);
        if (end == s.c_str() || *end != '\0' || errno == ERANGE) {
            return false;
        }
        if (v < std::numeric_limits<int32_t>::min() || v > std::numeric_limits<int32_t>::max()) {
            return false;
        }
        *out = static_cast<int32_t>(v);
        return true;
    }
    if (p >= json.size()) {
        return false;
    }
    const char* end = nullptr;
    long long v = 0;
    if (!ParseStrictIntToken(json.c_str() + p, &end, &v)) {
        return false;
    }
    if (v < std::numeric_limits<int32_t>::min() || v > std::numeric_limits<int32_t>::max()) {
        return false;
    }
    *out = static_cast<int32_t>(v);
    return true;
}

bool ExtractStringArray(const std::string& json, const char* key, std::vector<std::string>* out) {
    if (!out || !key) {
        return false;
    }
    size_t p = 0;
    if (!FindKeyColon(json, key, &p)) {
        return false;
    }
    if (p >= json.size() || json[p] != '[') {
        return false;
    }
    size_t end = 0;
    if (!FindMatchingBracket(json, p, '[', ']', &end)) {
        return false; /* unterminated array */
    }
    const std::string arr = json.substr(p + 1, end - p - 1);
    out->clear();
    size_t i = 0;
    bool expect_value = true;
    bool saw_value = false;
    while (i < arr.size()) {
        while (i < arr.size() &&
               (arr[i] == ' ' || arr[i] == '\t' || arr[i] == '\n' || arr[i] == '\r')) {
            ++i;
        }
        if (i >= arr.size()) {
            break;
        }
        if (arr[i] == ',') {
            if (expect_value) {
                return false; /* leading/double comma */
            }
            expect_value = true;
            ++i;
            continue;
        }
        if (!expect_value) {
            return false; /* missing comma between values */
        }
        if (arr[i] != '"') {
            return false;
        }
        std::string v;
        if (!ParseQuotedString(arr, &i, &v)) {
            return false;
        }
        out->push_back(std::move(v));
        expect_value = false;
        saw_value = true;
        (void)saw_value;
    }
    if (expect_value && !arr.empty()) {
        /* Trailing comma or only whitespace after comma. */
        size_t j = 0;
        SkipWs(arr, &j);
        if (j < arr.size()) {
            return false;
        }
        /* empty array OK; trailing comma: expect_value true after comma with nothing left */
        for (size_t k = arr.size(); k > 0;) {
            --k;
            if (arr[k] == ' ' || arr[k] == '\t' || arr[k] == '\n' || arr[k] == '\r') {
                continue;
            }
            if (arr[k] == ',') {
                return false;
            }
            break;
        }
    }
    return true;
}

bool SplitObjects(const std::string& arr, std::vector<std::string>* out) {
    if (!out) {
        return false;
    }
    out->clear();
    const char* body = arr.c_str();
    size_t n = arr.size();
    size_t base = 0;
    /* Accept either a raw array body or a full "[...]" span. */
    if (n > 0 && arr[0] == '[') {
        size_t close = 0;
        if (!FindMatchingBracket(arr, 0, '[', ']', &close) || close + 1 != n) {
            /* Allow trailing whitespace after ']'. */
            if (!FindMatchingBracket(arr, 0, '[', ']', &close)) {
                return false;
            }
            size_t t = close + 1;
            while (t < n && (arr[t] == ' ' || arr[t] == '\t' || arr[t] == '\n' || arr[t] == '\r')) {
                ++t;
            }
            if (t != n) {
                return false;
            }
        }
        body = arr.c_str() + 1;
        n = close - 1;
        base = 1;
    }
    int depth = 0;
    size_t start = std::string::npos;
    bool in_str = false;
    bool expect_value = true;
    bool saw_value = false;
    for (size_t i = 0; i < n; ++i) {
        const char c = body[i];
        if (in_str) {
            if (c == '\\') {
                if (i + 1 < n) {
                    ++i;
                } else {
                    return false; /* truncated escape */
                }
                continue;
            }
            if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        if (c == ',') {
            if (depth != 0) {
                continue; /* commas inside objects are fine */
            }
            if (expect_value) {
                return false;
            }
            expect_value = true;
            continue;
        }
        if (c == '{') {
            if (depth == 0) {
                if (!expect_value) {
                    return false;
                }
                start = base + i;
                expect_value = false;
                saw_value = true;
            }
            ++depth;
        } else if (c == '}') {
            if (depth == 0) {
                return false;
            }
            --depth;
            if (depth == 0 && start != std::string::npos) {
                out->push_back(arr.substr(start, (base + i) - start + 1));
                start = std::string::npos;
            }
        } else if (depth == 0) {
            /* Non-object top-level tokens are rejected (object arrays only). */
            return false;
        }
    }
    if (in_str || depth != 0) {
        out->clear();
        return false; /* truncated / unbalanced */
    }
    if (expect_value && saw_value) {
        out->clear();
        return false; /* trailing comma */
    }
    return true;
}

bool ExtractObjectArray(const std::string& json, const char* key, std::vector<std::string>* out) {
    if (!out || !key) {
        return false;
    }
    size_t p = 0;
    if (!FindKeyColon(json, key, &p)) {
        return false;
    }
    if (p >= json.size() || json[p] != '[') {
        return false;
    }
    size_t end = 0;
    if (!FindMatchingBracket(json, p, '[', ']', &end)) {
        return false;
    }
    /* Reject trailing junk after the array (e.g. "[{}] junk"). */
    size_t t = end + 1;
    SkipWs(json, &t);
    if (t < json.size() && json[t] != ',' && json[t] != '}') {
        return false;
    }
    return SplitObjects(json.substr(p, end - p + 1), out);
}

namespace {

bool ParseDisplayValue(const std::string& s, size_t* i, std::string* out);
bool ParseDisplayArray(const std::string& s, size_t* i, std::vector<std::string>* elems);

bool ParseDisplayArray(const std::string& s, size_t* i, std::vector<std::string>* elems) {
    if (!i || !elems || *i >= s.size() || s[*i] != '[') {
        return false;
    }
    ++(*i);
    elems->clear();
    bool expect = true;
    for (;;) {
        SkipWs(s, i);
        if (*i >= s.size()) {
            return false;
        }
        if (s[*i] == ']') {
            ++(*i);
            return !expect || elems->empty();
        }
        if (s[*i] == ',') {
            if (expect) {
                return false;
            }
            expect = true;
            ++(*i);
            continue;
        }
        if (!expect) {
            return false;
        }
        std::string v;
        if (!ParseDisplayValue(s, i, &v)) {
            return false;
        }
        elems->push_back(std::move(v));
        expect = false;
    }
}

bool ParseDisplayValue(const std::string& s, size_t* i, std::string* out) {
    if (!i || !out) {
        return false;
    }
    SkipWs(s, i);
    if (*i >= s.size()) {
        return false;
    }
    const size_t start = *i;
    if (s[*i] == '"') {
        return ParseQuotedString(s, i, out);
    }
    if (s[*i] == '{') {
        size_t close = 0;
        if (!FindMatchingBracket(s, *i, '{', '}', &close)) {
            return false;
        }
        *out = s.substr(start, close - start + 1);
        *i = close + 1;
        return true;
    }
    if (s[*i] == '[') {
        std::vector<std::string> elems;
        if (!ParseDisplayArray(s, i, &elems)) {
            return false;
        }
        std::string raw = "[";
        for (size_t e = 0; e < elems.size(); ++e) {
            if (e) {
                raw.push_back(',');
            }
            if (!elems[e].empty() && elems[e][0] == '{') {
                raw += elems[e];
            } else if (elems[e] == "true" || elems[e] == "false" || elems[e] == "null" ||
                       (!elems[e].empty() &&
                        (elems[e][0] == '-' || (elems[e][0] >= '0' && elems[e][0] <= '9')))) {
                raw += elems[e];
            } else {
                raw.push_back('"');
                EscapeAppend(&raw, elems[e].c_str());
                raw.push_back('"');
            }
        }
        raw.push_back(']');
        *out = std::move(raw);
        return true;
    }
    if (s.compare(*i, 4, "true") == 0) {
        *i += 4;
        *out = "true";
        return true;
    }
    if (s.compare(*i, 5, "false") == 0) {
        *i += 5;
        *out = "false";
        return true;
    }
    if (s.compare(*i, 4, "null") == 0) {
        *i += 4;
        *out = "null";
        return true;
    }
    if (s[*i] == '-' || (s[*i] >= '0' && s[*i] <= '9')) {
        size_t j = *i;
        if (s[j] == '-') {
            ++j;
        }
        while (j < s.size() && s[j] >= '0' && s[j] <= '9') {
            ++j;
        }
        *out = s.substr(*i, j - *i);
        *i = j;
        return !out->empty() && *out != "-";
    }
    return false;
}

} // namespace

bool ParseObjectFields(const std::string& json,
                       std::vector<std::pair<std::string, std::string>>* fields) {
    if (!fields) {
        return false;
    }
    fields->clear();
    size_t i = 0;
    SkipWs(json, &i);
    if (i >= json.size() || json[i] != '{') {
        return false;
    }
    ++i;
    bool expect = true;
    for (;;) {
        SkipWs(json, &i);
        if (i >= json.size()) {
            return false;
        }
        if (json[i] == '}') {
            if (expect && !fields->empty()) {
                return false; /* trailing comma */
            }
            return true;
        }
        if (json[i] == ',') {
            if (expect) {
                return false;
            }
            expect = true;
            ++i;
            continue;
        }
        if (!expect) {
            return false;
        }
        std::string key;
        if (!ParseQuotedString(json, &i, &key)) {
            return false;
        }
        SkipWs(json, &i);
        if (i >= json.size() || json[i] != ':') {
            return false;
        }
        ++i;
        std::string val;
        if (!ParseDisplayValue(json, &i, &val)) {
            return false;
        }
        fields->emplace_back(std::move(key), std::move(val));
        expect = false;
    }
}

bool ParseArrayElements(const std::string& arr, std::vector<std::string>* elems) {
    if (!elems) {
        return false;
    }
    size_t i = 0;
    SkipWs(arr, &i);
    if (i >= arr.size() || arr[i] != '[') {
        return false;
    }
    if (!ParseDisplayArray(arr, &i, elems)) {
        return false;
    }
    SkipWs(arr, &i);
    return i >= arr.size(); /* reject trailing junk after array */
}

void Writer::CommaIfNeeded() {
    if (need_comma_.empty()) {
        return;
    }
    if (!expecting_value_ && need_comma_.back()) {
        buf_.push_back(',');
    }
    expecting_value_ = false;
    need_comma_.back() = true;
}

void Writer::BeginObject() {
    CommaIfNeeded();
    buf_.push_back('{');
    need_comma_.push_back(false);
    expecting_value_ = true;
}

void Writer::EndObject() {
    if (!need_comma_.empty()) {
        need_comma_.pop_back();
    }
    buf_.push_back('}');
    expecting_value_ = false;
    if (!need_comma_.empty()) {
        need_comma_.back() = true;
    }
}

void Writer::BeginArray() {
    CommaIfNeeded();
    buf_.push_back('[');
    need_comma_.push_back(false);
    expecting_value_ = true;
}

void Writer::EndArray() {
    if (!need_comma_.empty()) {
        need_comma_.pop_back();
    }
    buf_.push_back(']');
    expecting_value_ = false;
    if (!need_comma_.empty()) {
        need_comma_.back() = true;
    }
}

void Writer::Key(const char* k) {
    CommaIfNeeded();
    buf_.push_back('"');
    EscapeAppend(&buf_, k ? k : "");
    buf_ += "\":";
    expecting_value_ = true;
    if (!need_comma_.empty()) {
        need_comma_.back() = false;
    }
}

void Writer::Str(const char* s) {
    CommaIfNeeded();
    buf_.push_back('"');
    if (s) {
        EscapeAppend(&buf_, s);
    }
    buf_.push_back('"');
}

void Writer::Str(const std::string& s) {
    CommaIfNeeded();
    buf_.push_back('"');
    EscapeAppend(&buf_, s.data(), s.size());
    buf_.push_back('"');
}

void Writer::Num(int64_t v) {
    CommaIfNeeded();
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%lld", static_cast<long long>(v));
    buf_ += tmp;
}

void Writer::Num(uint64_t v) {
    CommaIfNeeded();
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%llu", static_cast<unsigned long long>(v));
    buf_ += tmp;
}

void Writer::Num(uint32_t v) {
    Num(static_cast<uint64_t>(v));
}

void Writer::Num(int32_t v) {
    Num(static_cast<int64_t>(v));
}

void Writer::Bool(bool v) {
    CommaIfNeeded();
    buf_ += v ? "true" : "false";
}

void Writer::Null() {
    CommaIfNeeded();
    buf_ += "null";
}

void Writer::HexStr(uint64_t v) {
    char tmp[24];
    snprintf(tmp, sizeof(tmp), "0x%llx", static_cast<unsigned long long>(v));
    Str(tmp);
}

void Writer::Raw(const std::string& json_fragment) {
    CommaIfNeeded();
    buf_ += json_fragment;
}

std::string Writer::Take() {
    std::string out = std::move(buf_);
    buf_.clear();
    need_comma_.clear();
    expecting_value_ = true;
    return out;
}

} // namespace json
} // namespace hdl
