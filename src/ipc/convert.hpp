#pragma once

#include "hdl/rpc/v1/types.pb.h"

#include "hdllib/hdllib.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl::ipc {

inline bool Utf8ToWide(std::string_view input, std::wstring* output) {
    if (!output || input.find('\0') != std::string_view::npos ||
        input.size() > static_cast<size_t>(INT_MAX)) {
        return false;
    }
    output->clear();
    if (input.empty()) {
        return true;
    }
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                           static_cast<int>(input.size()), nullptr, 0);
    if (needed <= 0) {
        return false;
    }
    output->resize(static_cast<size_t>(needed));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                               static_cast<int>(input.size()), output->data(), needed) == needed;
}

inline bool WideToUtf8(const wchar_t* input, size_t length, std::string* output) {
    if (!output || (!input && length) || length > static_cast<size_t>(INT_MAX)) {
        return false;
    }
    output->clear();
    if (!length) {
        return true;
    }
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input,
                                           static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return false;
    }
    output->resize(static_cast<size_t>(needed));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, static_cast<int>(length),
                               output->data(), needed, nullptr, nullptr) == needed;
}

template <size_t N> std::string FixedString(const char (&value)[N]) {
    size_t length = 0;
    while (length < N && value[length] != '\0') {
        ++length;
    }
    return std::string(value, length);
}

template <size_t N> bool FixedWideString(const wchar_t (&value)[N], std::string* output) {
    size_t length = 0;
    while (length < N && value[length] != L'\0') {
        ++length;
    }
    return WideToUtf8(value, length, output);
}

inline void ToProto(const HdlRegionInfo& in, rpc::v1::RegionInfo* out) {
    out->set_base(in.base);
    out->set_size(in.size);
    out->set_protection(in.protect);
    out->set_state(in.state);
    out->set_type(in.type);
}

inline bool ToProto(const HdlModuleInfo& in, rpc::v1::ModuleInfo* out) {
    out->set_base(in.base);
    out->set_size(in.size);
    std::string path;
    if (!FixedWideString(in.path, &path)) {
        return false;
    }
    out->set_path(std::move(path));
    return true;
}

inline void ToProto(const HdlHealthInfo& in, rpc::v1::HealthInfo* out) {
    out->set_pid(in.pid);
    out->set_thread_count(in.thread_count);
    out->set_handle_count(in.handle_count);
    out->set_flags(in.flags);
    out->set_working_set(in.working_set);
    out->set_private_bytes(in.private_bytes);
    out->set_user_time_100ns(in.user_time_100ns);
    out->set_kernel_time_100ns(in.kernel_time_100ns);
    out->set_cpu_percent(in.cpu_percent);
    out->set_gui_hung(in.gui_hung != 0);
    out->set_last_exception_code(in.last_exception_code);
    out->set_last_exception_address(in.last_exception_addr);
    out->set_last_exception_tick_ms(in.last_exception_tick_ms);
}

inline void ToProto(const HdlThreadInfo& in, rpc::v1::ThreadInfo* out) {
    out->set_tid(in.tid);
    out->set_suspend_count(in.suspend_count);
    out->set_user_time_100ns(in.user_time_100ns);
    out->set_kernel_time_100ns(in.kernel_time_100ns);
    out->set_start_address(in.start_address);
}

inline void ToProto(const HdlFingerprintTag& in, rpc::v1::FingerprintTag* out) {
    out->set_category(static_cast<rpc::v1::FingerprintCategory>(in.category));
    out->set_confidence(in.confidence);
    out->set_flags(in.flags);
    out->set_id(FixedString(in.id));
    out->set_evidence(FixedString(in.evidence));
}

inline void ToProto(const HdlEvent& in, rpc::v1::Event* out) {
    out->set_type(static_cast<rpc::v1::EventType>(in.type));
    out->set_code(in.code);
    out->set_timestamp_ms(in.timestamp_ms);
    out->set_address(in.address);
    out->set_detail(in.detail);
}

inline void ToProto(const HdlPatternResult& in, rpc::v1::PatternResult* out) {
    out->set_match_address(in.match_addr);
    out->set_resolved_address(in.resolved_addr);
    out->set_module_base(in.module_base);
    out->set_rva(in.rva);
}

inline void ToProto(const HdlPointerPath& in, rpc::v1::PointerPath* out) {
    out->set_static_base(in.static_base);
    const uint32_t depth = (std::min)(in.depth, 8u);
    for (uint32_t index = 0; index < depth; ++index) {
        out->add_offsets(in.offsets[index]);
    }
}

inline bool FromProto(const rpc::v1::PointerPath& in, HdlPointerPath* out) {
    if (!out || in.offsets_size() > 8) {
        return false;
    }
    *out = {};
    out->static_base = in.static_base();
    out->depth = static_cast<uint32_t>(in.offsets_size());
    for (int index = 0; index < in.offsets_size(); ++index) {
        out->offsets[index] = in.offsets(index);
    }
    return true;
}

inline void ToProto(const HdlStructField& in, rpc::v1::StructField* out) {
    out->set_offset(in.offset);
    out->set_kind(static_cast<rpc::v1::FieldKind>(in.kind));
    out->set_value(in.value);
}

inline void ToProto(const HdlCandidate& in, rpc::v1::Candidate* out) {
    out->set_id(in.id);
    out->set_kind(static_cast<rpc::v1::CandidateKind>(in.kind));
    out->set_confidence(in.confidence);
    out->set_address(in.address);
    out->set_module_base(in.module_base);
    out->set_rva(in.rva);
    out->set_field_offset(in.field_offset);
    out->set_flags(in.flags);
    out->set_tag(FixedString(in.tag));
}

inline void ToProto(const HdlSynthesizedPattern& in, rpc::v1::SynthesizedPattern* out) {
    out->set_pattern(FixedString(in.pattern));
    out->set_pattern_offset(in.pattern_offset);
    out->set_rip_displacement_offset(in.rip_disp_offset);
    out->set_rip_instruction_length(in.rip_instr_len);
    out->set_match_address(in.match_addr);
    out->set_resolved_address(in.resolved_addr);
    out->set_unique_hits(in.unique_hits);
}

inline void ToProto(const HdlHeatField& in, rpc::v1::HeatField* out) {
    out->set_offset(in.offset);
    out->set_changes(in.changes);
    out->set_kind(static_cast<rpc::v1::FieldKind>(in.kind));
    out->set_size(in.reserved);
    out->set_last_value(in.last_value);
}

inline void ToProto(const HdlCaveInfo& in, rpc::v1::CaveInfo* out) {
    out->set_address(in.addr);
    out->set_size(in.size);
    out->set_region_base(in.region_base);
}

inline void ToProto(const HdlHookHit& in, rpc::v1::HookHit* out) {
    out->set_hook_id(in.hook_id);
    out->set_timestamp_ms(in.timestamp_ms);
    out->set_return_value(in.return_value);
    for (uint32_t i = 0; i < (std::min)(in.arg_count, 8u); ++i) {
        out->add_arguments(in.args[i]);
    }
    out->set_caller(in.caller);
    for (uint32_t i = 0; i < (std::min)(in.frame_count, 8u); ++i) {
        out->add_frames(in.frames[i]);
    }
}

inline void ToProto(const HdlDisasmBackendInfo& in, rpc::v1::DisasmBackendInfo* out) {
    out->set_id(in.id);
    out->set_name(FixedString(in.name));
}

inline void ToProto(const HdlInsn& in, rpc::v1::Instruction* out) {
    out->set_address(in.addr);
    out->set_length(in.length);
    out->set_flags(in.flags);
    out->set_branch_target(in.branch_target);
    out->set_rip_displacement_offset(in.rip_disp_offset);
    out->set_rip_displacement_size(in.rip_disp_size);
    out->set_mnemonic(FixedString(in.mnemonic));
    out->set_operands(FixedString(in.op_str));
}

inline void ToProto(const HdlStubResult& in, rpc::v1::StubResult* out) {
    out->set_stub_address(in.stub_va);
    out->set_stolen_bytes(in.stolen_bytes);
    out->set_code(in.code, (std::min)(in.code_size, static_cast<uint32_t>(sizeof(in.code))));
}

inline void ToProto(const HdlPatchInfo& in, rpc::v1::PatchInfo* out) {
    out->set_handle(in.handle);
    out->set_address(in.addr);
    out->set_size(in.size);
    out->set_enabled(in.enabled != 0);
    out->set_name(FixedString(in.name));
}

inline void ToProto(const HdlSectionInfo& in, rpc::v1::SectionInfo* out) {
    out->set_name(FixedString(in.name));
    out->set_virtual_address(in.va);
    out->set_virtual_size(in.vsize);
    out->set_raw_size(in.raw_size);
    out->set_characteristics(in.characteristics);
}

inline void ToProto(const HdlExportInfo& in, rpc::v1::ExportInfo* out) {
    out->set_name(FixedString(in.name));
    out->set_ordinal(in.ordinal);
    out->set_forwarder(in.forwarder != 0);
    out->set_rva(in.rva);
    out->set_virtual_address(in.va);
}

inline void ToProto(const HdlImportInfo& in, rpc::v1::ImportInfo* out) {
    out->set_module(FixedString(in.module));
    out->set_name(FixedString(in.name));
    out->set_ordinal(in.ordinal);
    out->set_iat_address(in.iat_va);
    out->set_bound_address(in.bound_va);
}

inline void ToProto(const HdlFunctionInfo& in, rpc::v1::FunctionInfo* out) {
    out->set_start(in.start);
    out->set_end(in.end);
    out->set_confidence(in.confidence);
    out->set_flags(in.flags);
}

inline void ToProto(const HdlXrefEdge& in, rpc::v1::XrefEdge* out) {
    out->set_from(in.from);
    out->set_to(in.to);
    out->set_kind(in.kind);
}

inline void ToProto(const HdlWatchInfo& in, rpc::v1::WatchInfo* out) {
    out->set_handle(in.handle);
    out->set_address(in.addr);
    out->set_size(in.size);
    out->set_kind(in.kind);
    out->set_type(static_cast<rpc::v1::WatchType>(in.type));
    out->set_thread_id(in.tid);
}

inline void ToProto(const HdlWatchHit& in, rpc::v1::WatchHit* out) {
    out->set_watch_handle(in.watch_handle);
    out->set_timestamp_ms(in.timestamp_ms);
    out->set_thread_id(in.tid);
    out->set_access(in.access);
    out->set_instruction_pointer(in.rip);
    out->set_accessed_address(in.accessed);
    out->set_size(in.size);
}

struct SearchValueStorage {
    int32_t type = HDL_VALUE_BYTES;
    std::vector<uint8_t> bytes;
    std::string text;
    std::wstring wide;

    const void* data() const {
        if (type == HDL_VALUE_BYTES) {
            return text.c_str();
        }
        if (type == HDL_VALUE_WSTRING) {
            return wide.data();
        }
        return bytes.empty() ? nullptr : bytes.data();
    }
    size_t size() const {
        if (type == HDL_VALUE_BYTES) {
            return 0;
        }
        if (type == HDL_VALUE_WSTRING) {
            return wide.size() * sizeof(wchar_t);
        }
        return bytes.size();
    }
};

template <typename T> void StoreScalar(T value, SearchValueStorage* out) {
    out->bytes.resize(sizeof(value));
    std::memcpy(out->bytes.data(), &value, sizeof(value));
}

inline bool FromProto(const rpc::v1::SearchValue& in, SearchValueStorage* out) {
    if (!out) {
        return false;
    }
    *out = {};
    switch (in.value_case()) {
    case rpc::v1::SearchValue::kAobPattern:
        if (in.aob_pattern().find('\0') != std::string::npos)
            return false;
        out->type = HDL_VALUE_BYTES;
        out->text = in.aob_pattern();
        return true;
    case rpc::v1::SearchValue::kSigned8:
        if (in.signed_8() < INT8_MIN || in.signed_8() > INT8_MAX)
            return false;
        out->type = HDL_VALUE_I8;
        StoreScalar(static_cast<int8_t>(in.signed_8()), out);
        return true;
    case rpc::v1::SearchValue::kUnsigned8:
        if (in.unsigned_8() > UINT8_MAX)
            return false;
        out->type = HDL_VALUE_U8;
        StoreScalar(static_cast<uint8_t>(in.unsigned_8()), out);
        return true;
    case rpc::v1::SearchValue::kSigned16:
        if (in.signed_16() < INT16_MIN || in.signed_16() > INT16_MAX)
            return false;
        out->type = HDL_VALUE_I16;
        StoreScalar(static_cast<int16_t>(in.signed_16()), out);
        return true;
    case rpc::v1::SearchValue::kUnsigned16:
        if (in.unsigned_16() > UINT16_MAX)
            return false;
        out->type = HDL_VALUE_U16;
        StoreScalar(static_cast<uint16_t>(in.unsigned_16()), out);
        return true;
    case rpc::v1::SearchValue::kSigned32:
        out->type = HDL_VALUE_I32;
        StoreScalar(in.signed_32(), out);
        return true;
    case rpc::v1::SearchValue::kUnsigned32:
        out->type = HDL_VALUE_U32;
        StoreScalar(in.unsigned_32(), out);
        return true;
    case rpc::v1::SearchValue::kSigned64:
        out->type = HDL_VALUE_I64;
        StoreScalar(in.signed_64(), out);
        return true;
    case rpc::v1::SearchValue::kUnsigned64:
        out->type = HDL_VALUE_U64;
        StoreScalar(in.unsigned_64(), out);
        return true;
    case rpc::v1::SearchValue::kFloat32:
        out->type = HDL_VALUE_F32;
        StoreScalar(in.float_32(), out);
        return true;
    case rpc::v1::SearchValue::kFloat64:
        out->type = HDL_VALUE_F64;
        StoreScalar(in.float_64(), out);
        return true;
    case rpc::v1::SearchValue::kNarrowBytes:
        out->type = HDL_VALUE_STRING;
        out->bytes.assign(in.narrow_bytes().begin(), in.narrow_bytes().end());
        return true;
    case rpc::v1::SearchValue::kWideText:
        out->type = HDL_VALUE_WSTRING;
        return Utf8ToWide(in.wide_text(), &out->wide);
    case rpc::v1::SearchValue::VALUE_NOT_SET:
        return false;
    }
    return false;
}

inline bool FromProto(const rpc::v1::FieldPredicate& in, HdlFieldPred* out) {
    if (!out)
        return false;
    *out = {};
    out->offset = in.offset();
    switch (in.predicate_case()) {
    case rpc::v1::FieldPredicate::kEqualsI32:
        out->kind = HDL_PRED_EQ_I32;
        out->a = in.equals_i32().value();
        return true;
    case rpc::v1::FieldPredicate::kEqualsF32: {
        out->kind = HDL_PRED_EQ_F32;
        uint32_t bits = 0;
        const float value = in.equals_f32().value();
        std::memcpy(&bits, &value, sizeof(bits));
        out->a = bits;
        return true;
    }
    case rpc::v1::FieldPredicate::kRangeI32:
        out->kind = HDL_PRED_RANGE_I32;
        out->a = in.range_i32().minimum();
        out->b = in.range_i32().maximum();
        return true;
    case rpc::v1::FieldPredicate::kRelativeLeI32:
        out->kind = HDL_PRED_LE_I32;
        out->a = in.relative_le_i32().relative_offset();
        return true;
    case rpc::v1::FieldPredicate::kPointer:
        out->kind = HDL_PRED_PTR;
        return true;
    case rpc::v1::FieldPredicate::kVtable:
        out->kind = HDL_PRED_VTABLE;
        return true;
    case rpc::v1::FieldPredicate::kEqualsU64:
        out->kind = HDL_PRED_EQ_U64;
        out->a = static_cast<int64_t>(in.equals_u64().value());
        return true;
    case rpc::v1::FieldPredicate::PREDICATE_NOT_SET:
        return false;
    }
    return false;
}

struct CallArguments {
    std::vector<HdlCallArg> args;
    std::vector<std::vector<uint8_t>> bytes;
    std::vector<std::wstring> wides;

    template <typename Repeated> bool Decode(const Repeated& values) {
        if (values.size() > 16)
            return false;
        args.resize(values.size());
        bytes.resize(values.size());
        wides.resize(values.size());
        for (int index = 0; index < values.size(); ++index) {
            const auto& value = values.Get(index);
            HdlCallArg& arg = args[index];
            switch (value.value_case()) {
            case rpc::v1::CallArgument::kUnsignedValue:
                arg.kind = HDL_CALL_ARG_U64;
                arg.u64 = value.unsigned_value();
                break;
            case rpc::v1::CallArgument::kSignedValue:
                arg.kind = HDL_CALL_ARG_I64;
                arg.u64 = static_cast<uint64_t>(value.signed_value());
                break;
            case rpc::v1::CallArgument::kPointerValue:
                arg.kind = HDL_CALL_ARG_PTR;
                arg.ptr = reinterpret_cast<const void*>(value.pointer_value());
                break;
            case rpc::v1::CallArgument::kBuffer:
                arg.kind = HDL_CALL_ARG_BUF;
                bytes[index].assign(value.buffer().begin(), value.buffer().end());
                arg.size = static_cast<uint32_t>(bytes[index].size());
                arg.ptr = bytes[index].data();
                break;
            case rpc::v1::CallArgument::kNarrowString:
                if (value.narrow_string().find('\0') != std::string::npos)
                    return false;
                arg.kind = HDL_CALL_ARG_CSTR;
                bytes[index].assign(value.narrow_string().begin(), value.narrow_string().end());
                bytes[index].push_back(0);
                arg.ptr = bytes[index].data();
                break;
            case rpc::v1::CallArgument::kWideString:
                if (!Utf8ToWide(value.wide_string(), &wides[index]))
                    return false;
                wides[index].push_back(L'\0');
                arg.kind = HDL_CALL_ARG_WSTR;
                arg.ptr = wides[index].data();
                break;
            case rpc::v1::CallArgument::kFloatValue: {
                arg.kind = HDL_CALL_ARG_F32;
                uint32_t bits = 0;
                const float scalar = value.float_value();
                std::memcpy(&bits, &scalar, sizeof(bits));
                arg.u64 = bits;
                break;
            }
            case rpc::v1::CallArgument::kDoubleValue: {
                arg.kind = HDL_CALL_ARG_F64;
                const double scalar = value.double_value();
                std::memcpy(&arg.u64, &scalar, sizeof(arg.u64));
                break;
            }
            case rpc::v1::CallArgument::VALUE_NOT_SET:
                return false;
            }
        }
        return true;
    }

    void SetResult(const HdlCallResult& result, rpc::v1::CallResult* out) const {
        out->set_return_value(result.return_value);
        out->set_last_error(result.last_error);
        for (uint32_t index = 0; index < static_cast<uint32_t>(args.size()); ++index) {
            if (args[index].kind == HDL_CALL_ARG_BUF) {
                auto* copy = out->add_buffer_copy_outs();
                copy->set_argument_index(index);
                copy->set_data(bytes[index].data(), bytes[index].size());
            }
        }
    }
};

} // namespace hdl::ipc
