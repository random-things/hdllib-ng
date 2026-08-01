#include "hdllib/hdllib.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/* DLL export surface is inject-technique callbacks only. Control channel is the named pipe. */

extern "C" {

LRESULT CALLBACK HdlHookProc(int code, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

void CALLBACK HdlWinEventProc(HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG id_object,
                              LONG id_child, DWORD event_thread, DWORD event_time) {
    (void)hook;
    (void)event;
    (void)hwnd;
    (void)id_object;
    (void)id_child;
    (void)event_thread;
    (void)event_time;
}

}  /* extern "C" */
