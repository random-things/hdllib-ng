// hdl_toy_arena — interactive mini-world for higher-level hdllib exercise.
//
// Not an injection matrix target. Built to drive locate / discover / pointer
// scan / cluster / heat / call / hooktrace against a living object graph:
//
//   World* ──► Entity[0..N]  (shared vtable, cross-instance `target` links)
//                 └──► Bag*  (heap leaf; realloc on `bag` / `respawn`)
//
// Static roots and unique markers are exported so hdlclient can resolve them
// as ground truth, then forget them and rediscover via constraints / paths.
//
// Usage:
//   hdl_toy_arena.exe [--window] [--auto <ms>] [--entities <n>]
//
// Console commands (stdin): help | status | tick [n] | damage <i> <amt> |
//   heal <i> | retarget <src> <dst> | bag <i> | respawn <i> | spawn | kill <i> |
//   attack <i> | quit
//
// After inject: resolve HdlToy* exports, then try ptrscan / discover-cluster /
// discover-pathvalidate across `bag` / `respawn`, heat around `damage`, etc.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <vector>

namespace {

constexpr uint64_t kWorldMagic = 0x544F59574F524C44ull; /* 'TOYWORLD' */
constexpr uint64_t kBagMagic = 0x544F594241473031ull;   /* 'TOYBAG01' */
constexpr uint32_t kMaxEntities = 8;

std::atomic<bool> g_run{true};
HANDLE g_exit_event = nullptr;

/* ---- Ground-truth markers (image-resident) ---- */

extern "C" {

__declspec(dllexport) const char HdlToyArenaString[] = "HDL_TOY_ARENA_v1";
__declspec(dllexport) const char* HdlToyArenaStringPtr = HdlToyArenaString;

__declspec(dllexport) __declspec(noinline) const char* HdlToyUseString(void) {
    volatile const char* p = HdlToyArenaString;
    return const_cast<const char*>(p);
}

#if defined(_MSC_VER)
#pragma optimize("", off)
#endif
/* Immediate 0x544F5931 ('TOY1') → bytes 31 59 4F 54 in the image. */
__declspec(dllexport) __declspec(noinline) int HdlToyCalc(int a, int b) {
    volatile int magic = 0x544F5931;
    volatile int x = a;
    volatile int y = b;
    return x + y + (magic ^ magic);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

struct ToyBag {
    uint64_t magic;
    int32_t gold;
    int32_t potions;
};

struct ToyEntity;

using ToyMethod = int64_t(__cdecl*)(ToyEntity* self, int64_t arg);

struct ToyEntity {
    ToyMethod* vtable;
    int32_t health;
    int32_t max_health;
    float x;
    float y;
    ToyEntity* target; /* cross-instance pointer */
    ToyBag* bag;       /* dynamic leaf */
    char name[16];
};

struct ToyWorld {
    uint64_t magic;
    uint32_t tick;
    uint32_t count;
    ToyEntity* player;
    ToyEntity* entities[kMaxEntities];
};

static int64_t __cdecl ToyEntityStrike(ToyEntity* self, int64_t amount) {
    if (!self || amount <= 0) {
        return self ? self->health : 0;
    }
    ToyEntity* victim = self->target ? self->target : self;
    victim->health -= static_cast<int32_t>(amount);
    if (victim->health < 0) {
        victim->health = 0;
    }
    return victim->health;
}

static ToyMethod g_entity_vt[1] = {&ToyEntityStrike};

/* Heap world; image-resident slot holds the live pointer (PointerScan base). */
static ToyWorld* g_world_ptr = nullptr;
__declspec(dllexport) ToyWorld* HdlToyWorldRoot = nullptr;

/*
 * Image-resident slots mirroring the live heap graph. PointerScan only walks
 * MEM_IMAGE, so a heap-only bag cannot be rediscovered after realloc without
 * an image slot that is updated when the leaf moves.
 */
__declspec(dllexport) ToyBag* HdlToyHeroBagRoot = nullptr;
__declspec(dllexport) ToyEntity* HdlToyEntitySlots[kMaxEntities] = {};

static void SyncStaticRoots() {
    HdlToyWorldRoot = g_world_ptr;
    for (uint32_t i = 0; i < kMaxEntities; ++i) {
        HdlToyEntitySlots[i] =
            (g_world_ptr && i < g_world_ptr->count) ? g_world_ptr->entities[i] : nullptr;
    }
    HdlToyHeroBagRoot = (g_world_ptr && g_world_ptr->player) ? g_world_ptr->player->bag : nullptr;
}

static ToyBag* AllocBag(int32_t gold, int32_t potions) {
    ToyBag* bag = nullptr;
    try {
        bag = new ToyBag{};
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
    bag->magic = kBagMagic;
    bag->gold = gold;
    bag->potions = potions;
    return bag;
}

static ToyEntity* AllocEntity(const char* name, int32_t hp, float x, float y, int32_t gold) {
    ToyEntity* e = nullptr;
    try {
        e = new ToyEntity{};
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
    std::memset(e, 0, sizeof(*e));
    e->vtable = g_entity_vt;
    e->health = hp;
    e->max_health = hp;
    e->x = x;
    e->y = y;
    e->bag = AllocBag(gold, 1);
    std::snprintf(e->name, sizeof(e->name), "%s", name);
    return e;
}

static void FreeEntity(ToyEntity* e) {
    if (!e) {
        return;
    }
    delete e->bag;
    e->bag = nullptr;
    delete e;
}

__declspec(dllexport) ToyWorld* HdlToyGetWorld(void) {
    return g_world_ptr;
}

__declspec(dllexport) ToyEntity* HdlToyGetEntity(uint32_t index) {
    if (!g_world_ptr || index >= g_world_ptr->count) {
        return nullptr;
    }
    return g_world_ptr->entities[index];
}

__declspec(dllexport) ToyBag* HdlToyGetBag(uint32_t index) {
    ToyEntity* e = HdlToyGetEntity(index);
    return e ? e->bag : nullptr;
}

#if defined(_MSC_VER)
#pragma optimize("", off)
#endif
__declspec(dllexport) __declspec(noinline) void HdlToyTickOnce(void) {
    if (!g_world_ptr) {
        return;
    }
    ++g_world_ptr->tick;
    for (uint32_t i = 0; i < g_world_ptr->count; ++i) {
        ToyEntity* e = g_world_ptr->entities[i];
        if (!e) {
            continue;
        }
        /* Slow drift so float scans / heat see motion without spam. */
        e->x += 0.05f * static_cast<float>((i % 3) - 1);
        e->y += 0.03f * static_cast<float>((i % 2) ? 1 : -1);
        if (e->bag) {
            e->bag->gold += static_cast<int32_t>(i == 0 ? 0 : 1);
        }
    }
}

__declspec(dllexport) __declspec(noinline) void HdlToyDamage(uint32_t index, int32_t amount) {
    ToyEntity* e = HdlToyGetEntity(index);
    if (!e) {
        return;
    }
    if (amount < 0) {
        amount = 0;
    }
    e->health -= amount;
    if (e->health < 0) {
        e->health = 0;
    }
}

__declspec(dllexport) __declspec(noinline) void HdlToyCallDamage(uint32_t index, int32_t amount) {
    HdlToyDamage(index, amount);
}

__declspec(dllexport) __declspec(noinline) void HdlToyAttack(uint32_t attacker_index) {
    ToyEntity* a = HdlToyGetEntity(attacker_index);
    if (!a || !a->vtable || !a->vtable[0]) {
        return;
    }
    a->vtable[0](a, 7);
}

__declspec(dllexport) __declspec(noinline) int HdlToyReallocBag(uint32_t index) {
    ToyEntity* e = HdlToyGetEntity(index);
    if (!e) {
        return 0;
    }
    const int32_t gold = e->bag ? e->bag->gold : 0;
    const int32_t potions = e->bag ? e->bag->potions : 0;
    delete e->bag;
    e->bag = AllocBag(gold + 3, potions + 1);
    SyncStaticRoots();
    return e->bag != nullptr;
}

__declspec(dllexport) __declspec(noinline) int HdlToyRespawn(uint32_t index) {
    ToyEntity* e = HdlToyGetEntity(index);
    if (!e) {
        return 0;
    }
    e->health = e->max_health;
    e->x = static_cast<float>(index) * 2.0f;
    e->y = 0.0f;
    return HdlToyReallocBag(index);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

__declspec(dllexport) int HdlToyRetarget(uint32_t src, uint32_t dst) {
    ToyEntity* a = HdlToyGetEntity(src);
    ToyEntity* b = HdlToyGetEntity(dst);
    if (!a || !b) {
        return 0;
    }
    a->target = b;
    return 1;
}

__declspec(dllexport) int HdlToySpawn(const char* name) {
    if (!g_world_ptr || g_world_ptr->count >= kMaxEntities) {
        return -1;
    }
    char buf[16];
    if (!name || !name[0]) {
        std::snprintf(buf, sizeof(buf), "mob%u", g_world_ptr->count);
        name = buf;
    }
    ToyEntity* e = AllocEntity(name, 40 + static_cast<int32_t>(g_world_ptr->count) * 5,
                               static_cast<float>(g_world_ptr->count) * 3.0f, 1.0f, 10);
    if (!e) {
        return -1;
    }
    const uint32_t idx = g_world_ptr->count++;
    g_world_ptr->entities[idx] = e;
    if (g_world_ptr->player) {
        e->target = g_world_ptr->player;
    }
    SyncStaticRoots();
    return static_cast<int>(idx);
}

__declspec(dllexport) int HdlToyKill(uint32_t index) {
    if (!g_world_ptr || index >= g_world_ptr->count || !g_world_ptr->entities[index]) {
        return 0;
    }
    ToyEntity* dead = g_world_ptr->entities[index];
    for (uint32_t i = 0; i < g_world_ptr->count; ++i) {
        if (g_world_ptr->entities[i] && g_world_ptr->entities[i]->target == dead) {
            g_world_ptr->entities[i]->target = g_world_ptr->player;
        }
    }
    FreeEntity(dead);
    for (uint32_t i = index; i + 1 < g_world_ptr->count; ++i) {
        g_world_ptr->entities[i] = g_world_ptr->entities[i + 1];
    }
    g_world_ptr->entities[--g_world_ptr->count] = nullptr;
    if (g_world_ptr->player == dead) {
        g_world_ptr->player = g_world_ptr->count ? g_world_ptr->entities[0] : nullptr;
    }
    SyncStaticRoots();
    return 1;
}

} // extern "C"

bool InitWorld(uint32_t entity_count) {
    if (entity_count < 2) {
        entity_count = 2;
    }
    if (entity_count > kMaxEntities) {
        entity_count = kMaxEntities;
    }
    try {
        g_world_ptr = new ToyWorld{};
    } catch (const std::bad_alloc&) {
        return false;
    }
    std::memset(g_world_ptr, 0, sizeof(*g_world_ptr));
    g_world_ptr->magic = kWorldMagic;

    ToyEntity* hero = AllocEntity("hero", 100, 0.0f, 0.0f, 50);
    if (!hero) {
        return false;
    }
    g_world_ptr->entities[0] = hero;
    g_world_ptr->player = hero;
    g_world_ptr->count = 1;

    for (uint32_t i = 1; i < entity_count; ++i) {
        char name[16];
        std::snprintf(name, sizeof(name), "mob%u", i);
        ToyEntity* m = AllocEntity(name, 50 + static_cast<int32_t>(i) * 10,
                                   static_cast<float>(i) * 4.0f, 2.0f, 5 + static_cast<int32_t>(i));
        if (!m) {
            break;
        }
        m->target = hero;
        g_world_ptr->entities[g_world_ptr->count++] = m;
    }
    hero->target = g_world_ptr->entities[g_world_ptr->count > 1 ? 1 : 0];
    SyncStaticRoots();
    return true;
}

void ShutdownWorld() {
    if (!g_world_ptr) {
        return;
    }
    for (uint32_t i = 0; i < g_world_ptr->count; ++i) {
        FreeEntity(g_world_ptr->entities[i]);
        g_world_ptr->entities[i] = nullptr;
    }
    delete g_world_ptr;
    g_world_ptr = nullptr;
    SyncStaticRoots();
}

void PrintStatus() {
    if (!g_world_ptr) {
        std::printf("(no world)\n");
        return;
    }
    std::printf("tick=%u count=%u player=%p world=%p world_root_slot=%p bag_root_slot=%p\n",
                g_world_ptr->tick, g_world_ptr->count, static_cast<void*>(g_world_ptr->player),
                static_cast<void*>(g_world_ptr), static_cast<void*>(&HdlToyWorldRoot),
                static_cast<void*>(&HdlToyHeroBagRoot));
    for (uint32_t i = 0; i < g_world_ptr->count; ++i) {
        ToyEntity* e = g_world_ptr->entities[i];
        if (!e) {
            continue;
        }
        std::printf("  [%u] %-8s hp=%d/%d pos=(%.2f,%.2f) self=%p target=%p bag=%p gold=%d\n", i,
                    e->name, e->health, e->max_health, e->x, e->y, static_cast<void*>(e),
                    static_cast<void*>(e->target), static_cast<void*>(e->bag),
                    e->bag ? e->bag->gold : -1);
    }
    std::fflush(stdout);
}

void PrintHelp() {
    std::printf(
        "commands:\n"
        "  help | status | tick [n] | damage <i> <amt> | heal <i>\n"
        "  retarget <src> <dst> | bag <i> | respawn <i> | spawn [name]\n"
        "  kill <i> | attack <i> | quit\n"
        "exports: HdlToyWorldRoot, HdlToyHeroBagRoot, HdlToyEntitySlots,\n"
        "         HdlToyGetWorld/Entity/Bag, HdlToyTickOnce,\n"
        "         HdlToyDamage/HdlToyCallDamage/Attack/ReallocBag/Respawn/Retarget/Spawn/Kill,\n"
        "         HdlToyCalc, HdlToyArenaString(+Ptr)\n"
        "ptrchain WorldRoot slot: +16 +32 +0  (player field, bag field, deref)\n"
        "ptrchain HeroBagRoot slot: +0  (dynamic leaf; updates on bag/respawn)\n");
    std::fflush(stdout);
}

bool HandleLine(const std::string& line) {
    if (line.empty()) {
        return true;
    }
    char cmd[32]{};
    char a1[64]{};
    char a2[64]{};
    const int n = sscanf_s(line.c_str(), "%31s %63s %63s", cmd, (unsigned)sizeof(cmd), a1,
                           (unsigned)sizeof(a1), a2, (unsigned)sizeof(a2));
    if (n < 1) {
        return true;
    }
    if (_stricmp(cmd, "help") == 0 || _stricmp(cmd, "?") == 0) {
        PrintHelp();
    } else if (_stricmp(cmd, "status") == 0 || _stricmp(cmd, "s") == 0) {
        PrintStatus();
    } else if (_stricmp(cmd, "tick") == 0) {
        const int times = n >= 2 ? std::atoi(a1) : 1;
        for (int i = 0; i < times; ++i) {
            HdlToyTickOnce();
        }
        PrintStatus();
    } else if (_stricmp(cmd, "damage") == 0 && n >= 3) {
        HdlToyCallDamage(static_cast<uint32_t>(std::atoi(a1)), std::atoi(a2));
        PrintStatus();
    } else if (_stricmp(cmd, "heal") == 0 && n >= 2) {
        ToyEntity* e = HdlToyGetEntity(static_cast<uint32_t>(std::atoi(a1)));
        if (e) {
            e->health = e->max_health;
        }
        PrintStatus();
    } else if (_stricmp(cmd, "retarget") == 0 && n >= 3) {
        HdlToyRetarget(static_cast<uint32_t>(std::atoi(a1)), static_cast<uint32_t>(std::atoi(a2)));
        PrintStatus();
    } else if (_stricmp(cmd, "bag") == 0 && n >= 2) {
        HdlToyReallocBag(static_cast<uint32_t>(std::atoi(a1)));
        PrintStatus();
    } else if (_stricmp(cmd, "respawn") == 0 && n >= 2) {
        HdlToyRespawn(static_cast<uint32_t>(std::atoi(a1)));
        PrintStatus();
    } else if (_stricmp(cmd, "spawn") == 0) {
        HdlToySpawn(n >= 2 ? a1 : "");
        PrintStatus();
    } else if (_stricmp(cmd, "kill") == 0 && n >= 2) {
        HdlToyKill(static_cast<uint32_t>(std::atoi(a1)));
        PrintStatus();
    } else if (_stricmp(cmd, "attack") == 0 && n >= 2) {
        HdlToyAttack(static_cast<uint32_t>(std::atoi(a1)));
        PrintStatus();
    } else if (_stricmp(cmd, "quit") == 0 || _stricmp(cmd, "exit") == 0) {
        g_run = false;
        return false;
    } else {
        std::printf("unknown command (try help): %s\n", cmd);
        std::fflush(stdout);
    }
    return true;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

DWORD WINAPI StdinThread(LPVOID) {
    char buf[256];
    while (g_run.load()) {
        if (!std::fgets(buf, sizeof(buf), stdin)) {
            break;
        }
        std::string line(buf);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (!HandleLine(line)) {
            break;
        }
    }
    g_run = false;
    return 0;
}

DWORD WINAPI AutoTickThread(LPVOID param) {
    const DWORD ms = static_cast<DWORD>(reinterpret_cast<uintptr_t>(param));
    while (g_run.load()) {
        Sleep(ms ? ms : 250);
        if (!g_run.load()) {
            break;
        }
        HdlToyTickOnce();
    }
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    (void)HdlToyUseString();
    (void)HdlToyCalc(1, 2);

    bool want_window = false;
    DWORD auto_ms = 0;
    uint32_t entities = 4;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--window") == 0) {
            want_window = true;
        } else if (_wcsicmp(argv[i], L"--auto") == 0 && i + 1 < argc) {
            auto_ms = static_cast<DWORD>(_wtoi(argv[++i]));
            if (auto_ms == 0) {
                auto_ms = 250;
            }
        } else if (_wcsicmp(argv[i], L"--entities") == 0 && i + 1 < argc) {
            entities = static_cast<uint32_t>(_wtoi(argv[++i]));
        } else if (_wcsicmp(argv[i], L"--help") == 0 || _wcsicmp(argv[i], L"-h") == 0) {
            std::wprintf(L"hdl_toy_arena [--window] [--auto ms] [--entities n]\n");
            return 0;
        } else {
            std::fwprintf(stderr, L"Unknown arg: %ls\n", argv[i]);
            return 2;
        }
    }

    if (!InitWorld(entities)) {
        std::fwprintf(stderr, L"InitWorld failed\n");
        return 3;
    }

    std::printf("hdl_toy_arena pid=%lu entities=%u auto_ms=%lu\n", GetCurrentProcessId(),
                g_world_ptr->count, static_cast<unsigned long>(auto_ms));
    PrintHelp();
    PrintStatus();

    HANDLE stdin_thr = CreateThread(nullptr, 0, StdinThread, nullptr, 0, nullptr);
    HANDLE auto_thr = nullptr;
    if (auto_ms) {
        auto_thr =
            CreateThread(nullptr, 0, AutoTickThread,
                         reinterpret_cast<LPVOID>(static_cast<uintptr_t>(auto_ms)), 0, nullptr);
    }

    HWND hwnd = nullptr;
    if (want_window) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"HdlToyArenaWnd";
        RegisterClassW(&wc);
        hwnd = CreateWindowExW(0, wc.lpszClassName, L"hdl_toy_arena", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 360, 200, nullptr, nullptr,
                               wc.hInstance, nullptr);
        if (hwnd) {
            ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            UpdateWindow(hwnd);
        }
    }

    if (want_window && hwnd) {
        MSG msg;
        while (g_run.load()) {
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) {
                    g_run = false;
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            Sleep(20);
        }
        DestroyWindow(hwnd);
    } else {
        while (g_run.load()) {
            Sleep(50);
        }
    }

    g_run = false;
    if (stdin_thr) {
        /* Unblock fgets if still waiting — best-effort; user can also type quit. */
        CancelSynchronousIo(stdin_thr);
        WaitForSingleObject(stdin_thr, 2000);
        CloseHandle(stdin_thr);
    }
    if (auto_thr) {
        WaitForSingleObject(auto_thr, 2000);
        CloseHandle(auto_thr);
    }
    ShutdownWorld();
    return 0;
}
