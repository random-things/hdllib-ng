#include "usage.hpp"

#include <cstdio>

void PrintUsage() {
    wprintf(LR"(hdlclient - inject hdllib and talk over a named pipe

Local inject (no pipe; former hdlinjector):
  hdlclient inject <pid> <dll-path> [--method NAME] [--hook-export NAME] [--stealth]
  hdlclient inject --title <substr> [--class <name>] <dll-path> [--method auto|...] [--stealth]
  hdlclient inject --recommend <pid> [dll-path] [--hook-export NAME] [--stealth]
  hdlclient inject --recommend --title <substr> [--class <name>] [dll-path] [--stealth]
  hdlclient inject --early-bird <exe-path> <dll-path> [--stealth]
  hdlclient inject --help
  hdlclient unload <pid> <dll-path> [--reload] [--modules]
  hdlclient reload <pid> <dll-path>

Pipe commands (DLL already loaded in <pid>):
  Global flags (before or after pid): --json  --store PATH
  Envelope: { "ok", "status", "cmd", "data", "error": { "code", "name", "hint" }|null }
  Stream verbs emit one aggregated JSON object (not NDJSON).
  Session: --session ID, else HDL_SESSION, else <store>.session or %%TEMP%%\hdl_session_<pid>.txt
  Mutating store/recipe/stabilize require --store PATH (load-mutate-save).

  hdlclient [--json] <pid> ping
  hdlclient <pid> modules [--stream]
  hdlclient <pid> regions [--stream]
  hdlclient <pid> threads [--stream]
  hdlclient <pid> health
  hdlclient <pid> health-veh on|off|status
  hdlclient <pid> log-file [path]   (omit path to clear file sink)
  hdlclient <pid> fingerprint [--stream] [--modules-only] [--no-imports]
  hdlclient <pid> events [--timeout MS] [--max N]
  hdlclient <pid> job create [--timeout MS]
  hdlclient <pid> job cancel <id>
  hdlclient <pid> job close <id>
  hdlclient <pid> resolve [--module NAME] <export>
  hdlclient <pid> call [--module NAME] [--timeout MS] [--job ID] <export> [ARGS...]
  hdlclient <pid> call --addr HEX [--main] [--timeout MS] [--job ID] [ARGS...]
  hdlclient <pid> vcall HEX_OBJ INDEX [--main] [--timeout MS] [--no-this] [ARGS...]
  hdlclient <pid> alloc SIZE [--protect RW|RWX]
  hdlclient <pid> alloc-near HEX_NEAR SIZE [--dist HEX]
  hdlclient <pid> free HEX_ADDR
  hdlclient <pid> caves [--min N] [--fill HEX] [--near HEX] [--image|--executable] [--module NAME]
  hdlclient <pid> protect HEX_ADDR SIZE R|RW|RX|RWX
  hdlclient <pid> flush-icache HEX_ADDR SIZE
  hdlclient <pid> disasm-backend list|get|set ID
  hdlclient <pid> disasm HEX_ADDR [--max N]
  hdlclient <pid> instrlen HEX_ADDR
  hdlclient <pid> sections [HEX_BASE]
  hdlclient <pid> exports [HEX_BASE]
  hdlclient <pid> imports [HEX_BASE]
  hdlclient <pid> functions [--module NAME] [--max N]
  hdlclient <pid> xrefs-from HEX_ADDR
  hdlclient <pid> xrefs-to HEX_ADDR [--module NAME] [--max N] [--exact]
  hdlclient <pid> resolve-function HEX_ADDR [--module NAME]
  hdlclient <pid> invalidate-fn-index [--module NAME]
  hdlclient <pid> vtable HEX_ADDR [--vtable]
  hdlclient <pid> rtti HEX_ADDR
  hdlclient <pid> watch list|unwatch HANDLE|refresh|hits [--max N] [--timeout MS]
              |hw HEX --size N --access exec|write|rw [--tid N]
              |page HEX SIZE --mode guard|noaccess
  hdlclient <pid> patch list|create HEX_ADDR HEX_BYTES [--name N]|enable|disable|remove HANDLE
  hdlclient <pid> stub [--kind abs_jmp|rel_jmp32|mov_rax_jmp|raw] [--target HEX] [--steal HEX] [--steal-min N] [--alloc|--no-alloc] [--raw HEX]
  hdlclient <pid> rip HEX_ADDR --disp N --len M
  hdlclient <pid> ptrchain HEX_BASE [+/-OFFSET ...]
  hdlclient <pid> modbase [--module NAME]
  hdlclient <pid> hooktrace HEX_ADDR [--args N]
  hdlclient <pid> hook HEX_TARGET HEX_DETOUR [--flags N]
  hdlclient <pid> hook-import DLL!Name | --dll X --import Y [--module M] [--args N]
  hdlclient <pid> unhook HEX_HANDLE
  hdlclient <pid> hook-enable HEX_HANDLE 0|1
  hdlclient <pid> hookhits [--timeout MS] [--max N]
  hdlclient <pid> read <hex-address> <size>
  hdlclient <pid> write <hex-address> <hex-bytes|@file>
  hdlclient <pid> scan --pattern "48 8B ?? ??" [--start HEX] [--size HEX] [--max N]
                       [--job ID] [--timeout MS]
  hdlclient <pid> scan --type TYPE --value VAL [--start HEX] [--size HEX] [--max N]
                       [--cmp exact|unknown|greater|less] [--unaligned] [--session ID]
                       [--job ID] [--timeout MS] [--image] [--executable] [--module NAME]
)");
    wprintf(LR"(  hdlclient <pid> resolve-pattern "AOB" [--module NAME] [--hit N] [--offset N]
  hdlclient <pid> xrefs HEX_ADDR [--module NAME]
  hdlclient <pid> ptrscan HEX [--depth N] [--max-offset N] [--max N] [--module NAME] [--store-add NAME]
  hdlclient <pid> probe HEX_ADDR [--size N]
  hdlclient <pid> discover-create
  hdlclient <pid> discover-close --session ID
  hdlclient <pid> discover-add --session ID --addr HEX [--kind address|function|object] [--tag T]
  hdlclient <pid> discover-constraint --session ID --size N --pred SPEC... [--module NAME] [--image] [--max N]
  hdlclient <pid> discover-synth --session ID --cand ID [--before N] [--after N] [--module NAME]
  hdlclient <pid> discover-pathscan HEX [--depth N] [--max-offset N] [--max N] [--module NAME] [--store-add NAME]
  hdlclient <pid> discover-pathvalidate HEX --base HEX --offs A,B,...
  hdlclient <pid> discover-scan --session ID --type T --value V [--tag T] [--module NAME] [--image] [--max N]
  hdlclient <pid> discover-watch --session ID --addr HEX [--args N]
  hdlclient <pid> discover-unwatch --session ID
  hdlclient <pid> discover-action-begin --session ID --name NAME
  hdlclient <pid> discover-action-end --session ID
  hdlclient <pid> discover-watch-region --session ID --addr HEX [--size N]
  hdlclient <pid> discover-heat --session ID --addr HEX
  hdlclient <pid> discover-rank --session ID --name NAME
  hdlclient <pid> discover-cluster --session ID --seed HEX --size N [--module NAME]
  hdlclient <pid> discover-cands --session ID
  hdlclient <pid> discover-watch-import --session ID --dll NAME --import NAME [--args N] [--module MOD]
  hdlclient <pid> discover-reset-heat --session ID --addr HEX
  hdlclient <pid> discover-export --session ID --out PATH
  hdlclient <pid> discover-import --session ID --in PATH
  hdlclient <pid> discover-diff --session ID --addr A --addr B ... [--size N]
  hdlclient <pid> discover-apply-watch --session ID --addr HEX [--size N]
  hdlclient <pid> discover-evidence --session ID --id CAND_ID
  hdlclient [--store PATH] <pid> session new|show|close
  hdlclient --store PATH <pid> store list|revalidate
  hdlclient --store PATH <pid> store add NAME export EXP [--kind K]
  hdlclient --store PATH <pid> store add NAME --pattern AOB [--addr HEX] ...
  hdlclient --store PATH <pid> recipe place|stitch INTEREST ...
  hdlclient <pid> recipe suggest|constrain|expand|action ...
    recipe action NAME WATCH --wait-ms N | --signal FILE
  hdlclient --store PATH <pid> stabilize CAND_ID   (requires resolved --session)
  Aliases: dcreate dclose dadd dscan … henable rpat
  hdlclient <pid> scan --next --session ID --cmp CMP [--value VAL] [--job ID] [--timeout MS]
  hdlclient <pid> scan --hits --session ID [--max N]
  hdlclient <pid> scan --close|--reset --session ID
  hdlclient <pid> inject <dll-path> [--target-pid N] [--method NAME] [--exe PATH] [--hook-export NAME]
  hdlclient <pid> unload <dll-path> [--target-pid N] [--reload]
  hdlclient <pid> shutdown [--modules]
  hdlclient <pid> reload <dll-path> [--target-pid N]
  hdlclient <pid> log <0-3>

Types: bytes, i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, string, wstring
Cmp:   exact, unknown, changed, unchanged, increased, decreased,
       increased_by, decreased_by, greater, less
Call args: u64:N | i64:N | f32:N | f64:N | cstr:TEXT | wstr:TEXT | buf:HEXBYTES | ptr:HEX

Inject methods: auto, create_remote_thread, nt_create_thread_ex, rtl_create_user_thread,
  queue_user_apc, set_windows_hook_ex, thread_hijack, manual_map, early_bird_apc,
  atom_bombing, module_stomp, section_map, window_subclass, instrumentation_callback,
  kernel_callback_table, veh, set_win_event_hook, rtl_remote_call, special_user_apc,
  thread_pool, etw_callback

Pipe: HdlFormatPipeName(pid) -> \\.\pipe\RPCControl_<hash> (HDL_PIPE: \\.\pipe\... or %%lu/%%08X)
)");
}
