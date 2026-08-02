#pragma once

#include "types.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Hooks (MinHook) ---- */

/* Custom detour; trampoline receives original if non-null. */

/*
 * Install a capture-only hook: calls original, records up to 8 integer-view args + return
 * into the hook-hit queue (also wakes PollEvents with HDL_EVENT_HOOK).
 */

enum { HDL_HOOK_MAX_FRAMES = 8 };

typedef struct HdlHookHit {
    uint64_t hook_id; /* target address (same as HdlHookHandle value) */
    uint64_t timestamp_ms;
    uint64_t return_value;
    uint32_t arg_count;
    uint32_t frame_count; /* 0..HDL_HOOK_MAX_FRAMES */
    uint64_t args[8];
    uint64_t caller;                      /* return address into the calling code (0 if unknown) */
    uint64_t frames[HDL_HOOK_MAX_FRAMES]; /* stack frames (best-effort) */
} HdlHookHit;

/*
 * Default SetWindowsHookEx callback exported by hdllib. Arbitrary inject targets should
 * export an equivalent LRESULT CALLBACK(int, WPARAM, LPARAM) that calls CallNextHookEx.
 */
HDL_API LRESULT CALLBACK HdlHookProc(int code, WPARAM wParam, LPARAM lParam);

/* Default SetWinEventHook (WINEVENT_INCONTEXT) callback. */
HDL_API void CALLBACK HdlWinEventProc(HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG id_object,
                                      LONG id_child, DWORD event_thread, DWORD event_time);

#ifdef __cplusplus
}
#endif
