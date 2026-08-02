#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace hdl {
namespace json {

/*
 * Minimal first-party JSON helpers — not a full-document validator.
 *
 * Design: keyed extractors and display-oriented parsers for trusted / mostly-well-
 * formed payloads (CLI envelopes, store files, discover import). They fail closed
 * on many common corruptions (truncated strings/arrays, bare-number junk after
 * whitespace, unbalanced object arrays) but are deliberately not RFC 8259
 * validators: trailing bytes after a top-level object, some malformed nested
 * values, and duplicate keys may still be accepted. Tighten later if untrusted
 * input becomes a requirement; do not assume success implies a unique valid parse.
 */

/* Escape UTF-8 into a JSON string body (no surrounding quotes). */
void EscapeAppend(std::string* out, const char* s, size_t n);
void EscapeAppend(std::string* out, const char* s);
std::string Escape(const std::string& s);

/* Keyed extractors: locate "key": <value> and parse that value only. */
bool ExtractString(const std::string& json, const char* key, std::string* out);
bool ExtractU64(const std::string& json, const char* key, uint64_t* out);
bool ExtractU32(const std::string& json, const char* key, uint32_t* out);
bool ExtractI32(const std::string& json, const char* key, int32_t* out);
bool ExtractStringArray(const std::string& json, const char* key, std::vector<std::string>* out);

/* Split a JSON array body (or "[...]" span) into top-level {...} objects.
 * Fail-closed on truncated / unbalanced input and trailing junk after "[...]". */
bool SplitObjects(const std::string& arr, std::vector<std::string>* out);

/* Locate "key":[ ... ] via matching brackets and split into objects.
 * Rejects non-structural trailing junk after the array within the parent object. */
bool ExtractObjectArray(const std::string& json, const char* key, std::vector<std::string>* out);

/* Display helpers for CLI text rendering — not full-document validation.
 * ParseObjectFields may accept trailing bytes after the first top-level object.
 * Nested object/array spans are kept raw without deep schema checks. */
bool ParseObjectFields(const std::string& json,
                       std::vector<std::pair<std::string, std::string>>* fields);

/* Parse a JSON array span ("[...]") into display-value elements (same value rules).
 * Rejects trailing junk after the array span. */
bool ParseArrayElements(const std::string& arr, std::vector<std::string>* elems);

/* Lightweight JSON builder. Addresses/ids typically as HexStr "0x...". */
class Writer {
  public:
    void BeginObject();
    void EndObject();
    void BeginArray();
    void EndArray();
    void Key(const char* k);
    void Str(const char* s);
    void Str(const std::string& s);
    void Num(int64_t v);
    void Num(uint64_t v);
    void Num(uint32_t v);
    void Num(int32_t v);
    void Bool(bool v);
    void Null();
    void HexStr(uint64_t v);
    void Raw(const std::string& json_fragment);
    std::string Take();

  private:
    std::string buf_;
    std::vector<bool> need_comma_;
    bool expecting_value_ = true;

    void CommaIfNeeded();
};

} // namespace json
} // namespace hdl
