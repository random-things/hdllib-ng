// Configurable victim process for injection matrix tests + locate/discover fixtures.
//
// Usage:
//   hdl_test_target --ready-handle <uint> --exit-handle <uint>
//                   [--window] [--alertable] [--integrity low|medium]
//
// Locate exports (for ground-truth checks after inject):
//   HdlTestLocateString / HdlTestLocateFn / HdlTestLocateLeaf /
//   HdlTestLocateRoot / HdlTestLocateObj
//
// Discover exports:
//   HdlTestDiscoverLeaf / HdlTestDiscoverAction / HdlTestDiscoverObjA|B /
//   HdlTestDiscoverDynLeaf / HdlTestDiscoverAllocDyn / HdlTestDiscoverFreeDyn /
//   HdlTestDiscoverDynRoot / HdlTestDiscoverDamage

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <new>

namespace {

std::atomic<bool> g_run{true};
HANDLE g_exit_event = nullptr;

/* ---- Locate fixtures (intentionally discoverable) ---- */

extern "C" {

/* Unique string in image; referenced by HdlTestLocateUseString (RIP xref). */
extern __declspec(dllexport) const char HdlTestLocateString[] = "HDL_LOCATE_STRING_v1";

/* Absolute pointer in .data for HDL_XREF_ABSOLUTE tests. */
__declspec(dllexport) const char* HdlTestLocateStringPtr = HdlTestLocateString;

__declspec(dllexport) __declspec(noinline) const char* HdlTestLocateUseString(void) {
    volatile const char* p = HdlTestLocateString;
    return const_cast<const char*>(p);
}

#if defined(_MSC_VER)
#pragma optimize("", off)
#endif
__declspec(dllexport) __declspec(noinline) int HdlTestLocateFn(int a, int b) {
    /* Immediate 0x48444C31 ('HDL1') appears as bytes 31 4C 44 48 in the image. */
    volatile int magic = 0x48444C31;
    volatile int x = a;
    volatile int y = b;
    volatile int s = x + y + (magic ^ magic);
    s ^= 0;
    s += 0;
    return s;
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

struct HdlTestLeaf {
    uint64_t magic; /* 0xD00DF00DCAFEBABE */
};

__declspec(dllexport) HdlTestLeaf HdlTestLocateLeaf = {0xD00DF00DCAFEBABEull};

static HdlTestLeaf* g_locate_mid = &HdlTestLocateLeaf;
__declspec(dllexport) HdlTestLeaf** HdlTestLocateRoot = &g_locate_mid;

struct HdlTestObj;

using HdlTestMethod = uint64_t(__cdecl*)(HdlTestObj* self, uint64_t x);

struct HdlTestObj {
    HdlTestMethod* vtable;
    uint32_t health;
    float x;
    float y;
    HdlTestLeaf* leaf;
};

static uint64_t __cdecl HdlTestObjAdd(HdlTestObj* self, uint64_t x) {
    return static_cast<uint64_t>(self->health) + x;
}

static HdlTestMethod g_locate_vt[1] = {&HdlTestObjAdd};

__declspec(dllexport) HdlTestObj HdlTestLocateObj = {
    g_locate_vt, 42, 1.5f, 2.5f, &HdlTestLocateLeaf,
};

/* ---- Discover fixtures ---- */

#if defined(_MSC_VER)
#pragma optimize("", off)
#endif
__declspec(dllexport) __declspec(noinline) void HdlTestDiscoverLeaf(void) {
    volatile int x = 0x44495343; /* 'DISC' */
    (void)x;
}

__declspec(dllexport) __declspec(noinline) void HdlTestDiscoverAction(void) {
    HdlTestDiscoverLeaf();
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

struct HdlTestDiscoverObj {
    HdlTestMethod* vtable;
    int32_t health;
    int32_t max_health;
    float pos_x;
    float pos_y;
};

static HdlTestMethod g_discover_vt[1] = {&HdlTestObjAdd};

__declspec(dllexport) HdlTestDiscoverObj HdlTestDiscoverObjA = {
    g_discover_vt, 80, 100, 3.0f, 4.0f,
};

__declspec(dllexport) HdlTestDiscoverObj HdlTestDiscoverObjB = {
    g_discover_vt, 50, 100, 5.0f, 6.0f,
};

__declspec(dllexport) void HdlTestDiscoverDamage(int32_t amount) {
    if (amount < 0) {
        amount = 0;
    }
    HdlTestDiscoverObjA.health -= amount;
    if (HdlTestDiscoverObjA.health < 0) {
        HdlTestDiscoverObjA.health = 0;
    }
}

static HdlTestLeaf* g_discover_dyn = nullptr;
__declspec(dllexport) HdlTestLeaf** HdlTestDiscoverDynRoot = &g_discover_dyn;

__declspec(dllexport) HdlTestLeaf* HdlTestDiscoverAllocDyn(void) {
    delete g_discover_dyn;
    g_discover_dyn = new (std::nothrow) HdlTestLeaf{0xD00DF00DCAFEBABEull};
    return g_discover_dyn;
}

__declspec(dllexport) void HdlTestDiscoverFreeDyn(void) {
    delete g_discover_dyn;
    g_discover_dyn = nullptr;
}

__declspec(dllexport) HdlTestLeaf* HdlTestDiscoverDynLeaf(void) {
    return g_discover_dyn;
}

} // extern "C"

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

DWORD WINAPI SpinThread(LPVOID) {
    while (g_run.load()) {
        YieldProcessor();
        if (g_exit_event && WaitForSingleObject(g_exit_event, 0) == WAIT_OBJECT_0) {
            break;
        }
    }
    return 0;
}

DWORD WINAPI AlertableThread(LPVOID) {
    while (g_run.load()) {
        SleepEx(50, TRUE);
        if (g_exit_event && WaitForSingleObject(g_exit_event, 0) == WAIT_OBJECT_0) {
            break;
        }
    }
    return 0;
}

DWORD WINAPI BusyThread(LPVOID) {
    while (g_run.load()) {
        if (g_exit_event) {
            if (WaitForSingleObject(g_exit_event, 50) == WAIT_OBJECT_0) {
                break;
            }
        } else {
            Sleep(50);
        }
    }
    return 0;
}

HANDLE HandleFromArg(const wchar_t* s) {
    return reinterpret_cast<HANDLE>(_wcstoui64(s, nullptr, 0));
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    /* Touch fixtures so the linker keeps them and rip-rel code is emitted. */
    (void)HdlTestLocateUseString();
    (void)HdlTestLocateFn(1, 2);
    (void)HdlTestLocateRoot;
    (void)HdlTestLocateObj.health;
    HdlTestDiscoverAction();
    (void)HdlTestDiscoverObjA.health;
    (void)HdlTestDiscoverObjB.health;
    (void)HdlTestDiscoverAllocDyn();
    (void)HdlTestDiscoverDynRoot;

    bool want_window = false;
    bool want_alertable = false;
    HANDLE ready_event = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--window") == 0) {
            want_window = true;
        } else if (_wcsicmp(argv[i], L"--alertable") == 0) {
            want_alertable = true;
        } else if (_wcsicmp(argv[i], L"--integrity") == 0 && i + 1 < argc) {
            ++i;
        } else if (_wcsicmp(argv[i], L"--ready-handle") == 0 && i + 1 < argc) {
            ready_event = HandleFromArg(argv[++i]);
        } else if (_wcsicmp(argv[i], L"--exit-handle") == 0 && i + 1 < argc) {
            g_exit_event = HandleFromArg(argv[++i]);
        } else if (_wcsicmp(argv[i], L"--ready-event") == 0 ||
                   _wcsicmp(argv[i], L"--exit-event") == 0) {
            fwprintf(stderr, L"Named events are no longer supported; use --*-handle\n");
            return 2;
        } else {
            fwprintf(stderr, L"Unknown arg: %ls\n", argv[i]);
            return 2;
        }
    }

    HANDLE worker = CreateThread(nullptr, 0, want_alertable ? AlertableThread : BusyThread, nullptr,
                                 0, nullptr);
    HANDLE spinner = CreateThread(nullptr, 0, SpinThread, nullptr, 0, nullptr);
    if (!worker || !spinner) {
        fwprintf(stderr, L"CreateThread failed: %lu\n", GetLastError());
        return 4;
    }

    HWND hwnd = nullptr;
    if (want_window) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"HdlTestTargetWnd";
        RegisterClassW(&wc);
        hwnd = CreateWindowExW(0, wc.lpszClassName, L"hdl_test_target", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 320, 200, nullptr, nullptr,
                               wc.hInstance, nullptr);
        if (!hwnd) {
            fwprintf(stderr, L"CreateWindowEx failed: %lu\n", GetLastError());
            g_run = false;
            WaitForSingleObject(worker, 2000);
            CloseHandle(worker);
            WaitForSingleObject(spinner, 2000);
            CloseHandle(spinner);
            return 5;
        }
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        UpdateWindow(hwnd);
    }

    if (ready_event) {
        SetEvent(ready_event);
    }

    if (want_window) {
        MSG msg;
        while (g_run.load()) {
            const HANDLE waits[1] = {g_exit_event};
            const DWORD nwaits = g_exit_event ? 1u : 0u;
            const DWORD wr =
                MsgWaitForMultipleObjects(nwaits, nwaits ? waits : nullptr, FALSE, 50, QS_ALLINPUT);
            if (g_exit_event && wr == WAIT_OBJECT_0) {
                break;
            }
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) {
                    g_run = false;
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if (hwnd) {
            DestroyWindow(hwnd);
        }
    } else if (g_exit_event) {
        WaitForSingleObject(g_exit_event, INFINITE);
    } else {
        while (g_run.load()) {
            Sleep(200);
        }
    }

    g_run = false;
    WaitForSingleObject(worker, 5000);
    WaitForSingleObject(spinner, 5000);
    CloseHandle(worker);
    CloseHandle(spinner);
    HdlTestDiscoverFreeDyn();
    return 0;
}
