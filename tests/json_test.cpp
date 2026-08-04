#include "json/json.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_failed = 0;

void Expect(bool cond, const char* msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        ++g_failed;
    }
}

} // namespace

int main() {
    using namespace hdl::json;

    Expect(Escape("a\"b\\c") == "a\\\"b\\\\c", "escape quotes/backslash");
    Expect(Escape("x\ny") == "x\\ny", "escape newline");
    Expect(Escape(std::string("\x01")) == "\\u0001", "escape control");

    {
        Writer w;
        w.BeginObject();
        w.Key("ok");
        w.Bool(true);
        w.Key("n");
        w.Num(42);
        w.Key("hex");
        w.HexStr(0x10);
        w.Key("arr");
        w.BeginArray();
        w.Str("a");
        w.Str("b");
        w.EndArray();
        w.EndObject();
        const std::string j = w.Take();
        Expect(j == "{\"ok\":true,\"n\":42,\"hex\":\"0x10\",\"arr\":[\"a\",\"b\"]}",
               "writer nesting");

        std::string name;
        Expect(ExtractString(j, "hex", &name) && name == "0x10", "writer→extract round-trip hex");
        uint64_t n = 0;
        Expect(ExtractU64(j, "n", &n) && n == 42, "writer→extract round-trip num");
        std::vector<std::string> tags;
        Expect(ExtractStringArray(j, "arr", &tags) && tags.size() == 2 && tags[0] == "a",
               "writer→extract round-trip array");
    }

    /* Escape round-trip through extract */
    {
        Writer w;
        w.BeginObject();
        w.Key("s");
        w.Str("line\nok\t\"x\\y");
        w.EndObject();
        std::string s;
        Expect(ExtractString(w.Take(), "s", &s) && s == "line\nok\t\"x\\y",
               "escape decode round-trip");
    }

    const std::string sample =
        "{\"name\":\"foo\",\"addr\":\"0x100\",\"count\":7,\"tags\":[\"a\",\"b\"]}";
    std::string name;
    Expect(ExtractString(sample, "name", &name) && name == "foo", "extract string");
    uint64_t addr = 0;
    Expect(ExtractU64(sample, "addr", &addr) && addr == 0x100, "extract u64 string");
    uint64_t count = 0;
    Expect(ExtractU64(sample, "count", &count) && count == 7, "extract u64 number");
    uint32_t count32 = 0;
    Expect(ExtractU32(sample, "count", &count32) && count32 == 7, "extract u32");
    int32_t counti = 0;
    Expect(ExtractI32(sample, "count", &counti) && counti == 7, "extract i32");
    std::vector<std::string> tags;
    Expect(ExtractStringArray(sample, "tags", &tags) && tags.size() == 2 && tags[0] == "a" &&
               tags[1] == "b",
           "extract string array");

    Expect(!ExtractString("{\"x\":1}", "missing", &name), "missing key fail-closed");
    Expect(!ExtractString("{\"x\":", "x", &name), "truncated string fail-closed");
    Expect(!ExtractString("{\"x\":\"unterminated}", "x", &name), "unterminated string fail-closed");
    Expect(!ExtractString("{\"x\":\"bad\\q\"}", "x", &name), "bad escape fail-closed");

    Expect(!ExtractU64("{\"n\":}", "n", &count), "empty number fail-closed");
    Expect(!ExtractU64("{\"n\":true}", "n", &count), "bool-as-number fail-closed");
    Expect(!ExtractU64("{\"n\":\"\"}", "n", &count), "empty numeric string fail-closed");
    Expect(!ExtractU64("{\"n\":\"xyz\"}", "n", &count), "malformed numeric string fail-closed");
    Expect(!ExtractU32("{\"n\":4294967296}", "n", &count32), "u32 overflow fail-closed");
    Expect(!ExtractI32("{\"n\":2147483648}", "n", &counti), "i32 overflow fail-closed");

    /* Strict bare-number token termination */
    Expect(!ExtractU64("{\"n\":12junk}", "n", &count), "trailing junk after u64 fail-closed");
    Expect(!ExtractU64("{\"n\":12 junk}", "n", &count), "space then junk after u64 fail-closed");
    Expect(!ExtractU64("{\"n\":12 : 3}", "n", &count), "space then colon junk fail-closed");
    Expect(!ExtractU64("{\"n\":1.5}", "n", &count), "fractional u64 fail-closed");
    Expect(!ExtractU64("{\"n\":+12}", "n", &count), "leading plus fail-closed");
    Expect(!ExtractU64("{\"n\":01}", "n", &count), "leading zero fail-closed");
    Expect(!ExtractI32("{\"n\":-7oops}", "n", &counti), "trailing junk after i32 fail-closed");
    Expect(!ExtractI32("{\"n\":-7 nope}", "n", &counti), "space then junk after i32 fail-closed");
    Expect(!ExtractI32("{\"n\":+7}", "n", &counti), "i32 leading plus fail-closed");
    Expect(ExtractI32("{\"n\":-7}", "n", &counti) && counti == -7, "negative i32 ok");
    Expect(ExtractU64("{\"n\":0}", "n", &count) && count == 0, "lone zero ok");
    Expect(ExtractU64("{\"n\":\"0x10\"}", "n", &count) && count == 0x10, "quoted hex ok");
    Expect(!ExtractU64("{\"n\":0x10}", "n", &count), "bare hex fail-closed");
    Expect(ExtractU64("{\"n\":12}", "n", &count) && count == 12, "clean u64 ok");
    Expect(ExtractU64("{\"n\":12 }", "n", &count) && count == 12, "u64 then ws before brace ok");

    Expect(!ExtractStringArray("{\"tags\":[\"a\",", "tags", &tags),
           "unterminated array fail-closed");
    Expect(!ExtractStringArray("{\"tags\":[\"a\",]}", "tags", &tags),
           "trailing comma array fail-closed");
    Expect(!ExtractStringArray("{\"tags\":[a]}", "tags", &tags), "unquoted array elem fail-closed");
    Expect(ExtractStringArray("{\"tags\":[]}", "tags", &tags) && tags.empty(), "empty array ok");

    std::vector<std::string> objs;
    Expect(SplitObjects("[{ \"a\":1 }, { \"b\":2 }]", &objs) && objs.size() == 2,
           "split objects count");
    Expect(objs[0].find("\"a\"") != std::string::npos, "split objects[0]");
    Expect(objs[1].find("\"b\"") != std::string::npos, "split objects[1]");
    Expect(!SplitObjects("[{ \"a\":1 }, { \"b\":2", &objs), "truncated object list fail-closed");
    Expect(!SplitObjects("[{ \"a\":1 },]", &objs), "trailing comma objects fail-closed");
    Expect(SplitObjects("[]", &objs) && objs.empty(), "empty object array ok");

    Expect(ExtractObjectArray("{\"items\":[{ \"a\":1 },{ \"b\":2 }]}", "items", &objs) &&
               objs.size() == 2,
           "extract object array");
    Expect(ExtractObjectArray("{\"items\":[{\"name\":\"x\",\"locators\":[{\"t\":1}]}]}", "items",
                              &objs) &&
               objs.size() == 1,
           "extract object array with nested arrays");
    Expect(!ExtractObjectArray("{\"items\":[{}] junk}", "items", &objs),
           "trailing junk after object array fail-closed");
    Expect(!ExtractObjectArray("{\"items\":[{ \"a\":1 }", "items", &objs),
           "truncated keyed object array fail-closed");
    Expect(!ExtractObjectArray("{\"items\":1}", "items", &objs),
           "non-array keyed value fail-closed");

    std::vector<std::pair<std::string, std::string>> fields;
    Expect(ParseObjectFields("{\"enabled\":true,\"n\":2}", &fields) && fields.size() == 2 &&
               fields[0].first == "enabled" && fields[0].second == "true",
           "parse object fields bool");
    Expect(ParseObjectFields("{\"matrix\":[[1,2],[3]]}", &fields) && fields.size() == 1 &&
               fields[0].second == "[[1,2],[3]]",
           "parse object fields preserves nested arrays");
    std::string deeply_nested = "{\"value\":";
    deeply_nested.append(129, '[');
    deeply_nested += '0';
    deeply_nested.append(129, ']');
    deeply_nested += '}';
    Expect(!ParseObjectFields(deeply_nested, &fields),
           "parse object fields rejects excessive nesting");
    std::vector<std::string> elems;
    Expect(ParseArrayElements("[\"a\",1,true]", &elems) && elems.size() == 3 && elems[2] == "true",
           "parse array elements");
    Expect(!ParseArrayElements("[1] junk", &elems), "array elements trailing junk fail-closed");

    if (g_failed) {
        fprintf(stderr, "%d json test(s) failed\n", g_failed);
        return 1;
    }
    printf("hdl_json_tests: ok\n");
    return 0;
}
