#pragma once

#include "hdllib/hdllib.h"

#include <cstddef>

namespace hdl {
namespace fp {

/* Null-terminated lists: last entry is nullptr. */
struct FpRule {
    uint32_t category;
    const char* id;
    uint32_t base_confidence;
    /* Module basename globs (lowercase match); '*' = any chars. nullptr list = no module req. */
    const wchar_t* const* module_globs;
    /* Optional IAT DLL basename globs (narrow, lowercase). */
    const char* const* import_modules;
    /* Optional IAT API name globs (narrow); any-of. */
    const char* const* import_names;
    /* If non-zero: require at least one import_names match for full confidence;
       module-only match uses base_confidence - 20 (min 10). */
    uint32_t prefer_import;
};

inline const wchar_t* const kMod_clr[] = {L"clr.dll", L"clrjit.dll", nullptr};
inline const wchar_t* const kMod_mscoree[] = {L"mscoree.dll", nullptr};
inline const wchar_t* const kMod_coreclr[] = {L"coreclr.dll", L"hostfxr.dll", L"hostpolicy.dll",
                                             nullptr};
inline const wchar_t* const kMod_mono[] = {L"mono-2.0-bdwgc.dll", L"mono.dll", L"mono-2.0-sgen.dll",
                                          nullptr};
inline const wchar_t* const kMod_jvm[] = {L"jvm.dll", L"java.dll", nullptr};
inline const wchar_t* const kMod_python[] = {L"python3*.dll", L"python2*.dll", L"python27.dll",
                                            nullptr};
inline const wchar_t* const kMod_lua[] = {L"lua*.dll", L"lua51.dll", L"lua52.dll", L"lua53.dll",
                                         L"lua54.dll", nullptr};
inline const wchar_t* const kMod_node[] = {L"node.dll", L"libnode.dll", nullptr};
inline const wchar_t* const kMod_electron[] = {L"electron.exe", L"electron.dll", L"chrome_elf.dll",
                                              nullptr};
inline const wchar_t* const kMod_cef[] = {L"libcef.dll", nullptr};
inline const wchar_t* const kMod_perl[] = {L"perl5*.dll", nullptr};
inline const wchar_t* const kMod_ruby[] = {L"x64-msvcrt-ruby*.dll", L"msvcrt-ruby*.dll", nullptr};
inline const wchar_t* const kMod_delphi[] = {L"borlndmm.dll", L"rtl2*.bpl", L"vcl*.bpl", nullptr};
inline const wchar_t* const kMod_ahk[] = {L"autohotkey*.dll", L"autohotkey*.exe", nullptr};

inline const wchar_t* const kMod_msvc[] = {L"vcruntime140*.dll", L"msvcp140*.dll", L"ucrtbase.dll",
                                          L"vcruntime140.dll", L"msvcp140.dll", nullptr};
inline const wchar_t* const kMod_mingw[] = {L"libgcc_s_*.dll", L"libstdc++-6.dll",
                                           L"libwinpthread-1.dll", nullptr};

inline const wchar_t* const kMod_user32[] = {L"user32.dll", nullptr};
inline const wchar_t* const kMod_gdi32[] = {L"gdi32.dll", nullptr};
inline const wchar_t* const kMod_winforms[] = {L"system.windows.forms.dll",
                                              L"system.windows.forms.ni.dll", nullptr};
inline const wchar_t* const kMod_wpf[] = {L"presentationframework.dll", L"presentationcore.dll",
                                         L"wpfgfx_*.dll", nullptr};
inline const wchar_t* const kMod_winui[] = {L"microsoft.ui.xaml.dll", L"windows.ui.xaml*.dll",
                                           nullptr};
inline const wchar_t* const kMod_mfc[] = {L"mfc140*.dll", L"mfc120*.dll", L"mfc140u.dll", nullptr};
inline const wchar_t* const kMod_qt5[] = {L"qt5core.dll", L"qt5gui.dll", L"qt5widgets.dll", nullptr};
inline const wchar_t* const kMod_qt6[] = {L"qt6core.dll", L"qt6gui.dll", L"qt6widgets.dll", nullptr};
inline const wchar_t* const kMod_gtk[] = {L"libgtk-3-0.dll", L"libglib-2.0-0.dll", L"libgtk-4-1.dll",
                                         nullptr};
inline const wchar_t* const kMod_wx[] = {L"wxbase*.dll", L"wxmsw*.dll", nullptr};
inline const wchar_t* const kMod_flutter[] = {L"flutter_windows.dll", nullptr};
inline const wchar_t* const kMod_imgui[] = {L"imgui.dll", L"cimgui.dll", nullptr};

inline const wchar_t* const kMod_gdiplus[] = {L"gdiplus.dll", nullptr};
inline const wchar_t* const kMod_d2d[] = {L"d2d1.dll", L"dwrite.dll", nullptr};
inline const wchar_t* const kMod_d3d9[] = {L"d3d9.dll", nullptr};
inline const wchar_t* const kMod_d3d11[] = {L"d3d11.dll", nullptr};
inline const wchar_t* const kMod_dxgi[] = {L"dxgi.dll", nullptr};
inline const wchar_t* const kMod_d3d12[] = {L"d3d12.dll", nullptr};
inline const wchar_t* const kMod_opengl[] = {L"opengl32.dll", L"glfw3.dll", L"glew32.dll", nullptr};
inline const wchar_t* const kMod_vulkan[] = {L"vulkan-1.dll", nullptr};
inline const wchar_t* const kMod_opencl[] = {L"opencl.dll", nullptr};
inline const wchar_t* const kMod_dawn[] = {L"dawn*.dll", L"webgpu_dawn.dll", nullptr};
inline const wchar_t* const kMod_sdl2[] = {L"sdl2.dll", L"sdl2.dll", nullptr};
inline const wchar_t* const kMod_sdl3[] = {L"sdl3.dll", nullptr};
inline const wchar_t* const kMod_sfml[] = {L"sfml-graphics*.dll", L"sfml-window*.dll", nullptr};
inline const wchar_t* const kMod_angle[] = {L"libegl.dll", L"libglesv2.dll", nullptr};

inline const wchar_t* const kMod_unity[] = {L"unityplayer.dll", L"gameassembly.dll", nullptr};
inline const wchar_t* const kMod_unreal[] = {L"ue4editor-*.dll", L"unrealeditor-*.dll",
                                            L"*-win64-shipping.exe", nullptr};
inline const wchar_t* const kMod_godot[] = {L"godot.*.dll", L"godot*.exe", nullptr};
inline const wchar_t* const kMod_cry[] = {L"crysystem.dll", L"cryrender*.dll", nullptr};
inline const wchar_t* const kMod_source2[] = {L"engine2.dll", L"materialsystem2.dll", nullptr};
inline const wchar_t* const kMod_gm[] = {L"runner.dll", nullptr};

inline const wchar_t* const kMod_webview2[] = {L"webview2loader.dll",
                                              L"embeddedbrowserwebview.dll", nullptr};
inline const wchar_t* const kMod_sciter[] = {L"sciter*.dll", nullptr};

inline const wchar_t* const kMod_xaudio[] = {L"xaudio2_*.dll", L"xaudio2_9.dll", nullptr};
inline const wchar_t* const kMod_mmdev[] = {L"mmdevapi.dll", nullptr};
inline const wchar_t* const kMod_fmod[] = {L"fmod*.dll", L"fmodstudio*.dll", nullptr};
inline const wchar_t* const kMod_bass[] = {L"bass.dll", L"bass*.dll", nullptr};
inline const wchar_t* const kMod_openal[] = {L"openal32.dll", L"soft_oal.dll", nullptr};

inline const wchar_t* const kMod_winhttp[] = {L"winhttp.dll", nullptr};
inline const wchar_t* const kMod_wininet[] = {L"wininet.dll", nullptr};
inline const wchar_t* const kMod_ws2[] = {L"ws2_32.dll", nullptr};
inline const wchar_t* const kMod_curl[] = {L"libcurl*.dll", L"curl.dll", nullptr};

inline const wchar_t* const kMod_steam[] = {L"steam_api64.dll", L"steam_api.dll", nullptr};
inline const wchar_t* const kMod_discord[] = {L"discord_game_sdk.dll", L"discord_partner_sdk.dll",
                                             L"discordhook64.dll", nullptr};
inline const wchar_t* const kMod_minhook[] = {L"minhook*.dll", nullptr};
inline const wchar_t* const kMod_detours[] = {L"detours.dll", L"syelog.dll", nullptr};

/* Import module / name helpers (narrow). */
inline const char* const kImpMod_user32[] = {"user32.dll", nullptr};
inline const char* const kImpNames_win32[] = {"CreateWindowExW", "CreateWindowExA", "GetMessageW",
                                             "GetMessageA", "DispatchMessageW", "DispatchMessageA",
                                             "PeekMessageW", "PeekMessageA", nullptr};
inline const char* const kImpMod_gdi32[] = {"gdi32.dll", nullptr};
inline const char* const kImpNames_gdi[] = {"BitBlt", "TextOutW", "TextOutA", "StretchBlt",
                                           "CreateCompatibleDC", nullptr};
inline const char* const kImpMod_d3d9[] = {"d3d9.dll", nullptr};
inline const char* const kImpNames_d3d9[] = {"Direct3DCreate9", "Direct3DCreate9Ex", nullptr};
inline const char* const kImpMod_d3d11[] = {"d3d11.dll", nullptr};
inline const char* const kImpNames_d3d11[] = {"D3D11CreateDevice", "D3D11CreateDeviceAndSwapChain",
                                             nullptr};
inline const char* const kImpMod_dxgi[] = {"dxgi.dll", nullptr};
inline const char* const kImpNames_dxgi[] = {"CreateDXGIFactory", "CreateDXGIFactory1",
                                            "CreateDXGIFactory2", nullptr};
inline const char* const kImpMod_d3d12[] = {"d3d12.dll", nullptr};
inline const char* const kImpNames_d3d12[] = {"D3D12CreateDevice", nullptr};
inline const char* const kImpMod_opengl[] = {"opengl32.dll", nullptr};
inline const char* const kImpNames_opengl[] = {"wglSwapBuffers", "wglCreateContext", "glClear",
                                              nullptr};
inline const char* const kImpMod_vulkan[] = {"vulkan-1.dll", nullptr};
inline const char* const kImpNames_vulkan[] = {"vkCreateInstance", "vkCreateDevice", nullptr};
inline const char* const kImpMod_d2d[] = {"d2d1.dll", nullptr};
inline const char* const kImpNames_d2d[] = {"D2D1CreateFactory", nullptr};

inline const FpRule kRules[] = {
    /* ---- Language / runtime ---- */
    {HDL_FP_CAT_RUNTIME, "dotnet_framework", 75, kMod_clr, nullptr, nullptr, 0},
    {HDL_FP_CAT_RUNTIME, "dotnet_framework", 55, kMod_mscoree, nullptr, nullptr, 0},
    {HDL_FP_CAT_RUNTIME, "coreclr", 90, kMod_coreclr, nullptr, nullptr, 0},
    {HDL_FP_CAT_RUNTIME, "mono", 85, kMod_mono, nullptr, nullptr, 0},
    {HDL_FP_CAT_RUNTIME, "jvm", 90, kMod_jvm, nullptr, nullptr, 0},
    {HDL_FP_CAT_LANGUAGE, "python", 90, kMod_python, nullptr, nullptr, 0},
    {HDL_FP_CAT_LANGUAGE, "lua", 80, kMod_lua, nullptr, nullptr, 0},
    {HDL_FP_CAT_RUNTIME, "nodejs", 85, kMod_node, nullptr, nullptr, 0},
    {HDL_FP_CAT_RUNTIME, "electron", 88, kMod_electron, nullptr, nullptr, 0},
    {HDL_FP_CAT_WEBHOST, "electron", 88, kMod_electron, nullptr, nullptr, 0},
    {HDL_FP_CAT_RUNTIME, "cef", 90, kMod_cef, nullptr, nullptr, 0},
    {HDL_FP_CAT_WEBHOST, "cef", 90, kMod_cef, nullptr, nullptr, 0},
    {HDL_FP_CAT_LANGUAGE, "perl", 85, kMod_perl, nullptr, nullptr, 0},
    {HDL_FP_CAT_LANGUAGE, "ruby", 85, kMod_ruby, nullptr, nullptr, 0},
    {HDL_FP_CAT_LANGUAGE, "delphi", 80, kMod_delphi, nullptr, nullptr, 0},
    {HDL_FP_CAT_LANGUAGE, "ahk", 85, kMod_ahk, nullptr, nullptr, 0},

    /* ---- Toolchain ---- */
    {HDL_FP_CAT_TOOLCHAIN, "msvc", 70, kMod_msvc, nullptr, nullptr, 0},
    {HDL_FP_CAT_TOOLCHAIN, "mingw", 85, kMod_mingw, nullptr, nullptr, 0},

    /* ---- UI ---- */
    {HDL_FP_CAT_UI, "win32", 35, kMod_user32, kImpMod_user32, kImpNames_win32, 1},
    {HDL_FP_CAT_UI, "gdi", 30, kMod_gdi32, kImpMod_gdi32, kImpNames_gdi, 1},
    {HDL_FP_CAT_UI, "winforms", 90, kMod_winforms, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "wpf", 92, kMod_wpf, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "winui", 90, kMod_winui, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "mfc", 88, kMod_mfc, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "qt5", 90, kMod_qt5, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "qt6", 90, kMod_qt6, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "gtk", 88, kMod_gtk, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "wxwidgets", 85, kMod_wx, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "flutter", 92, kMod_flutter, nullptr, nullptr, 0},
    {HDL_FP_CAT_UI, "imgui", 70, kMod_imgui, nullptr, nullptr, 0},

    /* ---- Graphics ---- */
    {HDL_FP_CAT_GRAPHICS, "gdiplus", 75, kMod_gdiplus, nullptr, nullptr, 0},
    {HDL_FP_CAT_GRAPHICS, "d2d", 80, kMod_d2d, kImpMod_d2d, kImpNames_d2d, 1},
    {HDL_FP_CAT_GRAPHICS, "d3d9", 70, kMod_d3d9, kImpMod_d3d9, kImpNames_d3d9, 1},
    {HDL_FP_CAT_GRAPHICS, "d3d11", 75, kMod_d3d11, kImpMod_d3d11, kImpNames_d3d11, 1},
    {HDL_FP_CAT_GRAPHICS, "d3d11", 55, kMod_dxgi, kImpMod_dxgi, kImpNames_dxgi, 1},
    {HDL_FP_CAT_GRAPHICS, "d3d12", 80, kMod_d3d12, kImpMod_d3d12, kImpNames_d3d12, 1},
    {HDL_FP_CAT_GRAPHICS, "opengl", 75, kMod_opengl, kImpMod_opengl, kImpNames_opengl, 1},
    {HDL_FP_CAT_GRAPHICS, "vulkan", 85, kMod_vulkan, kImpMod_vulkan, kImpNames_vulkan, 1},
    {HDL_FP_CAT_GRAPHICS, "opencl", 85, kMod_opencl, nullptr, nullptr, 0},
    {HDL_FP_CAT_GRAPHICS, "webgpu_dawn", 88, kMod_dawn, nullptr, nullptr, 0},
    {HDL_FP_CAT_GRAPHICS, "sdl2", 88, kMod_sdl2, nullptr, nullptr, 0},
    {HDL_FP_CAT_GRAPHICS, "sdl3", 88, kMod_sdl3, nullptr, nullptr, 0},
    {HDL_FP_CAT_GRAPHICS, "sfml", 85, kMod_sfml, nullptr, nullptr, 0},
    {HDL_FP_CAT_GRAPHICS, "angle", 85, kMod_angle, nullptr, nullptr, 0},

    /* ---- Engines ---- */
    {HDL_FP_CAT_ENGINE, "unity", 95, kMod_unity, nullptr, nullptr, 0},
    {HDL_FP_CAT_ENGINE, "unreal", 90, kMod_unreal, nullptr, nullptr, 0},
    {HDL_FP_CAT_ENGINE, "godot", 90, kMod_godot, nullptr, nullptr, 0},
    {HDL_FP_CAT_ENGINE, "cryengine", 90, kMod_cry, nullptr, nullptr, 0},
    {HDL_FP_CAT_ENGINE, "source2", 85, kMod_source2, nullptr, nullptr, 0},
    {HDL_FP_CAT_ENGINE, "gamemaker", 70, kMod_gm, nullptr, nullptr, 0},

    /* ---- Web host ---- */
    {HDL_FP_CAT_WEBHOST, "webview2", 92, kMod_webview2, nullptr, nullptr, 0},
    {HDL_FP_CAT_WEBHOST, "sciter", 88, kMod_sciter, nullptr, nullptr, 0},

    /* ---- Audio ---- */
    {HDL_FP_CAT_AUDIO, "xaudio2", 85, kMod_xaudio, nullptr, nullptr, 0},
    {HDL_FP_CAT_AUDIO, "wasapi", 40, kMod_mmdev, nullptr, nullptr, 0},
    {HDL_FP_CAT_AUDIO, "fmod", 90, kMod_fmod, nullptr, nullptr, 0},
    {HDL_FP_CAT_AUDIO, "bass", 85, kMod_bass, nullptr, nullptr, 0},
    {HDL_FP_CAT_AUDIO, "openal", 85, kMod_openal, nullptr, nullptr, 0},

    /* ---- Network ---- */
    {HDL_FP_CAT_NETWORK, "winhttp", 75, kMod_winhttp, nullptr, nullptr, 0},
    {HDL_FP_CAT_NETWORK, "wininet", 70, kMod_wininet, nullptr, nullptr, 0},
    {HDL_FP_CAT_NETWORK, "winsock", 25, kMod_ws2, nullptr, nullptr, 0},
    {HDL_FP_CAT_NETWORK, "curl", 88, kMod_curl, nullptr, nullptr, 0},

    /* ---- Tooling ---- */
    {HDL_FP_CAT_TOOLING, "steam", 90, kMod_steam, nullptr, nullptr, 0},
    {HDL_FP_CAT_TOOLING, "discord", 85, kMod_discord, nullptr, nullptr, 0},
    {HDL_FP_CAT_TOOLING, "minhook", 80, kMod_minhook, nullptr, nullptr, 0},
    {HDL_FP_CAT_TOOLING, "detours", 80, kMod_detours, nullptr, nullptr, 0},
};

inline constexpr size_t kRuleCount = sizeof(kRules) / sizeof(kRules[0]);

/* Strong UI frameworks that suppress ambient win32/gdi primary claims. */
inline const char* const kStrongUiIds[] = {"wpf",     "winforms", "winui",  "qt5",  "qt6",
                                          "gtk",     "wxwidgets", "flutter", "mfc", "electron",
                                          nullptr};

/* Strong graphics that suppress ambient gdi primary. */
inline const char* const kStrongGfxIds[] = {"d3d9",  "d3d11", "d3d12", "opengl", "vulkan",
                                           "d2d",   "sdl2",  "sdl3",  "sfml",   "webgpu_dawn",
                                           "angle", nullptr};

}  // namespace fp
}  // namespace hdl
