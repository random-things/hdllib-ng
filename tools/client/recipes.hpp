#pragma once

#include "ipc_ops.hpp"
#include "store.hpp"

#include <functional>
#include <string>
#include <vector>

namespace hdlcli {

using LogFn = std::function<void(const std::wstring&)>;

struct ControllerState {
    PipeClient* client = nullptr;
    uint32_t pid = 0;
    uint64_t discover_session = 0;
    InterestStore store;
    std::wstring store_path;
    HdlSynthesizedPattern last_synth{};
    std::vector<HdlCandidate> last_rank;
    uint64_t last_object = 0;
    uint64_t last_stub_va = 0;
    uint64_t last_patch_handle = 0;
    HdlStubResult last_stub{};
    std::string last_patch_bytes_hex;
    uint64_t last_patch_addr = 0;
    uint64_t last_cave_addr = 0;
    uint64_t last_cave_size = 0;
    /* Last successful pointer path (discover-pathscan / ptrscan / pathvalidate). */
    HdlPointerPath last_path{};
    bool last_path_valid = false;
    std::string last_path_module;
    /* Optional wait hook for recipe action (one-shot uses --wait-ms / --signal FILE). */
    std::function<bool()> wait_enter;
    /* When true, newly created discover sessions are written to the session sidecar. */
    bool persist_session = true;
};

struct StabilizeResult {
    int rc = 1;
    std::string interest_name;
};

/* Record a path result for later `store add … path`. */
void RememberPath(ControllerState* st, const HdlPointerPath& path, const wchar_t* module_or_null);

/* Resolve locators; rebuild stubs. If apply, recreate patch ledger (and enable when
 * enabled_intent is set). Default apply=false keeps patches address-only. */
int RevalidateStore(ControllerState& st, LogFn log, bool apply = false);

StabilizeResult RecipeAction(ControllerState& st, const char* action_name, uint64_t watch_fn,
                             LogFn log, const std::function<bool()>& wait_user);

int RecipeConstrain(ControllerState& st, uint32_t object_size,
                    const std::vector<HdlFieldPred>& preds, uint32_t search_flags,
                    const wchar_t* module, LogFn log);

/* Find/score caves near target; record cave locator (or AllocNear fallback) on interest. */
int RecipePlace(ControllerState& st, const char* interest_name, uint64_t near_addr,
                const wchar_t* module, LogFn log);

/* BuildStub + PatchCreate/Enable jmp at target; store stub+patch locators on interest. */
int RecipeStitch(ControllerState& st, const char* interest_name, uint64_t target_addr, int32_t kind,
                 uint32_t steal_min, LogFn log);

/* Register discover watch-region on object base; print manual action/heat steps. */
int RecipeExpandStruct(ControllerState& st, uint64_t base, uint32_t size, LogFn log);

/* Print fingerprint-driven next-step suggestions (does not auto-run). */
int RecipeSuggest(ControllerState& st, LogFn log);

StabilizeResult StabilizeCandidate(ControllerState& st, uint64_t cand_id, const wchar_t* module,
                                   LogFn log);

bool EnsureDiscoverSession(ControllerState& st, LogFn log);

/* Attach a path locator to interest NAME (in-memory). Caller owns load/save. */
bool StoreAddPathInterest(ControllerState& st, const char* name, const HdlPointerPath& path,
                          const wchar_t* module_or_null, std::wstring* err);

/* Pick best cave: nearer first, then larger size. */
size_t ScoreBestCave(const std::vector<HdlCaveInfo>& caves, uint64_t near_addr);

} // namespace hdlcli
