#include "hdl/rpc/v1/call.pb.h"
#include "hdl/rpc/v1/search.pb.h"
#include "hdl/rpc/v1/types.pb.h"
#include "ipc/convert.hpp"

#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>

namespace {
int passed = 0, failed = 0;

void Expect(const char* name, bool condition) {
    if (condition) {
        ++passed;
    } else {
        ++failed;
        std::printf("FAIL: %s\n", name);
    }
}

template <typename T> void RoundTrip(const char* name, const T& input) {
    std::string bytes, output_bytes;
    T output;
    const bool ok = input.SerializeToString(&bytes) && output.ParseFromString(bytes) &&
                    output.SerializeToString(&output_bytes) && bytes == output_bytes;
    if (ok)
        ++passed;
    else {
        ++failed;
        std::printf("FAIL: %s\n", name);
    }
}

void TestMessages() {
    using namespace hdl::rpc::v1;
    SearchScope scope;
    scope.set_start(0x1000);
    scope.set_size(0x2000);
    scope.set_flags(7);
    scope.set_module("mód.dll");
    RoundTrip("SearchScope", scope);
    auto search_value = [](auto setter, const char* name) {
        SearchValue value;
        setter(&value);
        RoundTrip(name, value);
    };
    search_value([](auto* v) { v->set_aob_pattern("48 8B ??"); }, "SearchValue/aob");
    search_value([](auto* v) { v->set_signed_8(-12); }, "SearchValue/i8");
    search_value([](auto* v) { v->set_unsigned_8(250); }, "SearchValue/u8");
    search_value([](auto* v) { v->set_signed_16(-1234); }, "SearchValue/i16");
    search_value([](auto* v) { v->set_unsigned_16(54321); }, "SearchValue/u16");
    search_value([](auto* v) { v->set_signed_32(-123456); }, "SearchValue/i32");
    search_value([](auto* v) { v->set_unsigned_32(4000000000u); }, "SearchValue/u32");
    search_value([](auto* v) { v->set_signed_64(-1234567890123ll); }, "SearchValue/i64");
    search_value([](auto* v) { v->set_unsigned_64(0xfedcba9876543210ull); }, "SearchValue/u64");
    search_value([](auto* v) { v->set_float_32(-0.0f); }, "SearchValue/f32");
    search_value([](auto* v) { v->set_float_64(1.0 / 3.0); }, "SearchValue/f64");
    search_value([](auto* v) { v->set_narrow_bytes("a\0b", 3); }, "SearchValue/bytes");
    search_value([](auto* v) { v->set_wide_text("雪だるま"); }, "SearchValue/text");
    RegionInfo region;
    region.set_base(1);
    region.set_size(2);
    region.set_protection(3);
    region.set_state(4);
    region.set_type(5);
    RoundTrip("RegionInfo", region);
    ModuleInfo module;
    module.set_base(1);
    module.set_size(2);
    module.set_path("C:/π/test.dll");
    RoundTrip("ModuleInfo", module);
    HealthInfo health;
    health.set_pid(1);
    health.set_thread_count(2);
    health.set_handle_count(3);
    health.set_flags(4);
    health.set_working_set(5);
    health.set_private_bytes(6);
    health.set_user_time_100ns(7);
    health.set_kernel_time_100ns(8);
    health.set_cpu_percent(9);
    health.set_gui_hung(true);
    health.set_last_exception_code(10);
    health.set_last_exception_address(11);
    health.set_last_exception_tick_ms(12);
    RoundTrip("HealthInfo", health);
    ThreadInfo thread;
    thread.set_tid(1);
    thread.set_suspend_count(2);
    thread.set_user_time_100ns(3);
    thread.set_kernel_time_100ns(4);
    thread.set_start_address(5);
    RoundTrip("ThreadInfo", thread);
    FingerprintTag fingerprint;
    fingerprint.set_category(FINGERPRINT_CATEGORY_LANGUAGE);
    fingerprint.set_confidence(99);
    fingerprint.set_flags(2);
    fingerprint.set_id("d3d11");
    fingerprint.set_evidence("module:d3d11.dll");
    RoundTrip("FingerprintTag", fingerprint);
    Event event;
    event.set_type(EVENT_TYPE_EXCEPTION);
    event.set_code(2);
    event.set_timestamp_ms(3);
    event.set_address(4);
    event.set_detail(5);
    RoundTrip("Event", event);
    PatternResult pattern;
    pattern.set_match_address(1);
    pattern.set_resolved_address(2);
    pattern.set_module_base(3);
    pattern.set_rva(4);
    RoundTrip("PatternResult", pattern);
    PointerPath path;
    path.set_static_base(1);
    path.add_offsets(-4);
    path.add_offsets(8);
    RoundTrip("PointerPath", path);
    StructField field;
    field.set_offset(1);
    field.set_kind(FIELD_KIND_VTABLE);
    field.set_value(3);
    RoundTrip("StructField", field);
    auto call_argument = [](auto setter, const char* name) {
        CallArgument value;
        setter(&value);
        RoundTrip(name, value);
    };
    call_argument([](auto* v) { v->set_unsigned_value(1); }, "CallArgument/u64");
    call_argument([](auto* v) { v->set_signed_value(-1); }, "CallArgument/i64");
    call_argument([](auto* v) { v->set_pointer_value(2); }, "CallArgument/pointer");
    call_argument([](auto* v) { v->set_buffer("a\0b", 3); }, "CallArgument/buffer");
    call_argument([](auto* v) { v->set_narrow_string("abc"); }, "CallArgument/cstr");
    call_argument([](auto* v) { v->set_wide_string("λ"); }, "CallArgument/wstr");
    call_argument([](auto* v) { v->set_float_value(3.5f); }, "CallArgument/float");
    call_argument([](auto* v) { v->set_double_value(-9.25); }, "CallArgument/double");
    BufferCopyOut copy;
    copy.set_argument_index(3);
    copy.set_data("xyz");
    RoundTrip("BufferCopyOut", copy);
    CallResult call_result;
    call_result.set_return_value(1);
    call_result.set_last_error(2);
    *call_result.add_buffer_copy_outs() = copy;
    RoundTrip("CallResult", call_result);
    HookHit hook;
    hook.set_hook_id(1);
    hook.set_timestamp_ms(2);
    hook.set_return_value(3);
    hook.add_arguments(4);
    hook.set_caller(5);
    hook.add_frames(6);
    RoundTrip("HookHit", hook);
    Candidate candidate;
    candidate.set_id(1);
    candidate.set_kind(CANDIDATE_KIND_FUNCTION);
    candidate.set_confidence(3);
    candidate.set_address(4);
    candidate.set_module_base(5);
    candidate.set_rva(6);
    candidate.set_field_offset(7);
    candidate.set_flags(8);
    candidate.set_tag("tag");
    RoundTrip("Candidate", candidate);
    auto predicate = [](auto setter, const char* name) {
        FieldPredicate value;
        value.set_offset(-4);
        setter(&value);
        RoundTrip(name, value);
    };
    predicate([](auto* v) { v->mutable_equals_i32()->set_value(-1); }, "FieldPredicate/eq_i32");
    predicate([](auto* v) { v->mutable_equals_f32()->set_value(2.5f); }, "FieldPredicate/eq_f32");
    predicate(
        [](auto* v) {
            v->mutable_range_i32()->set_minimum(-2);
            v->mutable_range_i32()->set_maximum(3);
        },
        "FieldPredicate/range");
    predicate([](auto* v) { v->mutable_relative_le_i32()->set_relative_offset(4); },
              "FieldPredicate/relative");
    predicate([](auto* v) { v->mutable_pointer(); }, "FieldPredicate/pointer");
    predicate([](auto* v) { v->mutable_vtable(); }, "FieldPredicate/vtable");
    predicate([](auto* v) { v->mutable_equals_u64()->set_value(9); }, "FieldPredicate/eq_u64");
    SynthesizedPattern synthesized;
    synthesized.set_pattern("48 ??");
    synthesized.set_pattern_offset(-1);
    synthesized.set_rip_displacement_offset(2);
    synthesized.set_rip_instruction_length(7);
    synthesized.set_match_address(3);
    synthesized.set_resolved_address(4);
    synthesized.set_unique_hits(1);
    RoundTrip("SynthesizedPattern", synthesized);
    HeatField heat;
    heat.set_offset(1);
    heat.set_changes(2);
    heat.set_kind(FIELD_KIND_ASCII);
    heat.set_size(4);
    heat.set_last_value(5);
    RoundTrip("HeatField", heat);
    CaveInfo cave;
    cave.set_address(1);
    cave.set_size(2);
    cave.set_region_base(3);
    RoundTrip("CaveInfo", cave);
    DisasmBackendInfo backend;
    backend.set_id(-1);
    backend.set_name("capstone");
    RoundTrip("DisasmBackendInfo", backend);
    Instruction instruction;
    instruction.set_address(1);
    instruction.set_length(2);
    instruction.set_flags(3);
    instruction.set_branch_target(4);
    instruction.set_rip_displacement_offset(5);
    instruction.set_rip_displacement_size(6);
    instruction.set_mnemonic("mov");
    instruction.set_operands("rax, rbx");
    RoundTrip("Instruction", instruction);
    StubResult stub;
    stub.set_stub_address(1);
    stub.set_stolen_bytes(2);
    stub.set_code("\x90\xcc", 2);
    RoundTrip("StubResult", stub);
    PatchInfo patch;
    patch.set_handle(1);
    patch.set_address(2);
    patch.set_size(3);
    patch.set_enabled(true);
    patch.set_name("patch");
    RoundTrip("PatchInfo", patch);
    SectionInfo section;
    section.set_name(".text");
    section.set_virtual_address(1);
    section.set_virtual_size(2);
    section.set_raw_size(3);
    section.set_characteristics(4);
    RoundTrip("SectionInfo", section);
    ExportInfo export_info;
    export_info.set_name("Fn");
    export_info.set_ordinal(1);
    export_info.set_forwarder(true);
    export_info.set_rva(2);
    export_info.set_virtual_address(3);
    RoundTrip("ExportInfo", export_info);
    ImportInfo import_info;
    import_info.set_module("k32.dll");
    import_info.set_name("Fn");
    import_info.set_ordinal(1);
    import_info.set_iat_address(2);
    import_info.set_bound_address(3);
    RoundTrip("ImportInfo", import_info);
    FunctionInfo function;
    function.set_start(1);
    function.set_end(2);
    function.set_confidence(3);
    function.set_flags(4);
    RoundTrip("FunctionInfo", function);
    XrefEdge edge;
    edge.set_from(1);
    edge.set_to(2);
    edge.set_kind(3);
    RoundTrip("XrefEdge", edge);
    WatchInfo watch;
    watch.set_handle(1);
    watch.set_address(2);
    watch.set_size(3);
    watch.set_kind(4);
    watch.set_type(WATCH_TYPE_PAGE);
    watch.set_thread_id(6);
    RoundTrip("WatchInfo", watch);
    WatchHit hit;
    hit.set_watch_handle(1);
    hit.set_timestamp_ms(2);
    hit.set_thread_id(3);
    hit.set_access(4);
    hit.set_instruction_pointer(5);
    hit.set_accessed_address(6);
    hit.set_size(7);
    RoundTrip("WatchHit", hit);
}

void TestConversionsAndValidation() {
    using namespace hdl::rpc::v1;

    std::wstring wide;
    std::string utf8;
    Expect("UTF-8 rejects malformed input", !hdl::ipc::Utf8ToWide("\xc3\x28", &wide));
    Expect("UTF-8 rejects embedded NUL", !hdl::ipc::Utf8ToWide(std::string_view("a\0b", 3), &wide));
    constexpr std::string_view module_utf8 = "m\xc3\xb3"
                                             "d.dll";
    Expect("UTF-8 converts valid text", hdl::ipc::Utf8ToWide(module_utf8, &wide));
    Expect("UTF-16 converts back to UTF-8",
           hdl::ipc::WideToUtf8(wide.data(), wide.size(), &utf8) && utf8 == module_utf8);

    SearchValue value;
    hdl::ipc::SearchValueStorage storage;
    Expect("SearchValue requires oneof", !hdl::ipc::FromProto(value, &storage));
    value.set_signed_8(128);
    Expect("SearchValue validates i8 range", !hdl::ipc::FromProto(value, &storage));
    value.set_wide_text(std::string("x\0y", 3));
    Expect("SearchValue validates wide text", !hdl::ipc::FromProto(value, &storage));
    value.set_unsigned_64(42);
    Expect("SearchValue oneof replaces prior case",
           value.value_case() == SearchValue::kUnsigned64 && hdl::ipc::FromProto(value, &storage));

    constexpr uint32_t float_bits = 0x80000000u;
    value.set_float_32(std::bit_cast<float>(float_bits));
    std::string bytes;
    SearchValue parsed;
    Expect("SearchValue float preserves exact bits",
           value.SerializeToString(&bytes) && parsed.ParseFromString(bytes) &&
               std::bit_cast<uint32_t>(parsed.float_32()) == float_bits);

    FieldPredicate predicate;
    HdlFieldPred domain_predicate{};
    Expect("FieldPredicate requires oneof", !hdl::ipc::FromProto(predicate, &domain_predicate));
    predicate.mutable_equals_i32()->set_value(1);
    predicate.mutable_vtable();
    Expect("FieldPredicate oneof replaces prior case",
           predicate.predicate_case() == FieldPredicate::kVtable &&
               hdl::ipc::FromProto(predicate, &domain_predicate) &&
               domain_predicate.kind == HDL_PRED_VTABLE);

    CallRequest call;
    call.add_arguments()->set_narrow_string(std::string("a\0b", 3));
    hdl::ipc::CallArguments arguments;
    Expect("CallArgument rejects embedded NUL C string", !arguments.Decode(call.arguments()));
    call.clear_arguments();
    for (int i = 0; i < 17; ++i) {
        call.add_arguments()->set_unsigned_value(static_cast<uint64_t>(i));
    }
    Expect("CallArgument enforces current argument limit", !arguments.Decode(call.arguments()));

    PointerPath path;
    HdlPointerPath domain_path{};
    for (int i = 0; i < 9; ++i) {
        path.add_offsets(i);
    }
    Expect("PointerPath enforces current depth limit", !hdl::ipc::FromProto(path, &domain_path));

    SearchFirstRequest search;
    Expect("Search defaults remain exact and natural",
           search.comparison() == SEARCH_COMPARISON_EXACT &&
               search.alignment() == SEARCH_ALIGNMENT_NATURAL);
    Expect("Enum helpers reject unknown values",
           SearchComparison_IsValid(SEARCH_COMPARISON_EXACT) && !SearchComparison_IsValid(999));
}
} // namespace

int main() {
    TestMessages();
    TestConversionsAndValidation();
    std::printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
