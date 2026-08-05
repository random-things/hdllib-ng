#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdDisasmBackend(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;
    if (ctx.argc >= 4 && _wcsicmp(ctx.argv[3], L"list") == 0) {
        SetMethod(req, hdl::rpc::Method::DisasmEnumBackends);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            return FailBadResp(ctx);
        }
        struct BackendItem {
            int32_t id;
            char name[64];
        };
        std::vector<BackendItem> items;
        items.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            HdlDisasmBackendInfo info{};
            if (!hdl::proto::TakeHdlDisasmBackendInfo(r, info)) {
                return FailBadResp(ctx);
            }
            BackendItem bi;
            bi.id = info.id;
            strncpy_s(bi.name, info.name, _TRUNCATE);
            items.push_back(bi);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("backends");
        w.BeginArray();
        for (const auto& bi : items) {
            w.BeginObject();
            w.Key("id");
            w.Num(bi.id);
            w.Key("name");
            w.Str(bi.name);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    }
    if (ctx.argc >= 4 && _wcsicmp(ctx.argv[3], L"get") == 0) {
        SetMethod(req, hdl::rpc::Method::DisasmGetBackend);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        int32_t id = 0;
        if (!r.TakePod(st) || !r.TakePod(id)) {
            return FailBadResp(ctx);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("id");
        w.Num(id);
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    }
    if (ctx.argc >= 5 && _wcsicmp(ctx.argv[3], L"set") == 0) {
        const int32_t id = _wtoi(ctx.argv[4]);
        SetMethod(req, hdl::rpc::Method::DisasmSetBackend);
        AppendPod(req, id);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        if (!r.TakePod(st)) {
            return FailBadResp(ctx);
        }
        return FinishStatus(ctx, st);
    }
    return FailUsage(ctx);
}

CommandResult CmdDisasm(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t max_insns = 16;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_insns = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::Disasm);
    AppendPod(req, addr);
    AppendPod(req, max_insns);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    struct InsnItem {
        uint64_t addr;
        char mnemonic[32];
        char op_str[128];
    };
    std::vector<InsnItem> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlInsn insn{};
        if (!hdl::proto::TakeHdlInsn(r, insn)) {
            return FailBadResp(ctx);
        }
        InsnItem it;
        it.addr = insn.addr;
        strncpy_s(it.mnemonic, insn.mnemonic, _TRUNCATE);
        strncpy_s(it.op_str, insn.op_str, _TRUNCATE);
        items.push_back(it);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("insns");
    w.BeginArray();
    for (const auto& it : items) {
        w.BeginObject();
        w.Key("addr");
        w.HexStr(it.addr);
        w.Key("mnemonic");
        w.Str(it.mnemonic);
        w.Key("op");
        w.Str(it.op_str);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdInstrLen(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::InstrLen);
    AppendPod(req, addr);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t len = 0;
    if (!r.TakePod(st) || !r.TakePod(len)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("len");
    w.Num(len);
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}
