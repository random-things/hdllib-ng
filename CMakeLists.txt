cmake_minimum_required(VERSION 3.16)
project(hdllib VERSION 0.1.0 LANGUAGES C CXX)

if(NOT WIN32)
  message(FATAL_ERROR "hdllib targets Windows only")
endif()

enable_language(ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(HDL_BUILD_TOOLS "Build hdlclient" ON)
option(HDL_BUILD_TESTS "Build hdl_tests / hdl_test_target" ON)
option(HDL_BUILD_TOYS "Build toy targets for higher-level hdllib exercise" ON)
option(HDL_CLIENT_TUI "Build hdlclient --tui with PDCurses" ON)
option(HDL_DISASM_ZYDIS "Enable Zydis disasm backend" ON)
option(HDL_DISASM_CAPSTONE "Enable Capstone disasm backend" ON)

if(NOT HDL_DISASM_ZYDIS AND NOT HDL_DISASM_CAPSTONE)
  message(FATAL_ERROR "At least one of HDL_DISASM_ZYDIS or HDL_DISASM_CAPSTONE must be ON")
endif()

include(FetchContent)

if(HDL_DISASM_ZYDIS)
  set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
  set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG v4.1.1
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(zydis)
endif()

if(HDL_DISASM_CAPSTONE)
  set(CAPSTONE_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
  FetchContent_Declare(capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG 5.0.3
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(capstone)
endif()

# Vendored MinHook (v1.3.3) — no CMake upstream in this tag
set(MINHOOK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook)
add_library(minhook STATIC
  ${MINHOOK_DIR}/src/buffer.c
  ${MINHOOK_DIR}/src/hook.c
  ${MINHOOK_DIR}/src/trampoline.c
  ${MINHOOK_DIR}/src/hde/hde64.c
)
target_include_directories(minhook PUBLIC ${MINHOOK_DIR}/include)
target_include_directories(minhook PRIVATE ${MINHOOK_DIR}/src)
target_compile_definitions(minhook PRIVATE UNICODE _UNICODE)
if(MSVC)
  target_compile_options(minhook PRIVATE /W3)
endif()

set(HDL_INJECT_SOURCES
  src/inject.cpp
  src/inject/common.cpp
  src/inject/select.cpp
  src/inject/create_remote_thread.cpp
  src/inject/nt_create_thread_ex.cpp
  src/inject/rtl_create_user_thread.cpp
  src/inject/queue_user_apc.cpp
  src/inject/set_windows_hook_ex.cpp
  src/inject/thread_hijack.cpp
  src/inject/manual_map.cpp
  src/inject/early_bird_apc.cpp
  src/inject/atom_bombing.cpp
  src/inject/module_stomp.cpp
  src/inject/section_map.cpp
  src/inject/window_subclass.cpp
  src/inject/instrumentation_callback.cpp
  src/inject/kernel_callback_table.cpp
  src/inject/veh.cpp
  src/inject/set_win_event_hook.cpp
  src/inject/rtl_remote_call.cpp
  src/inject/special_user_apc.cpp
  src/inject/thread_pool.cpp
  src/inject/etw_callback.cpp
  src/log.cpp
  src/env.cpp
)

add_library(hdl_inject STATIC ${HDL_INJECT_SOURCES})
target_include_directories(hdl_inject
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_definitions(hdl_inject PRIVATE UNICODE _UNICODE)
target_compile_options(hdl_inject PRIVATE /W4 /EHsc /permissive-)
target_link_libraries(hdl_inject PUBLIC Psapi Advapi32)

add_library(hdllib SHARED
  src/dllmain.cpp
  src/api.cpp
  src/core.cpp
  src/memory.cpp
  src/hooks.cpp
  src/hooks_trace.asm
  src/ipc_server.cpp
  src/ipc/framing.cpp
  src/ipc/common.cpp
  src/ipc/server.cpp
  src/ipc/dispatch.cpp
  src/ipc/handlers_basic.cpp
  src/ipc/handlers_search.cpp
  src/ipc/handlers_call.cpp
  src/ipc/handlers_hooks.cpp
  src/ipc/handlers_locate.cpp
  src/ipc/handlers_discover.cpp
  src/ipc/handlers_place.cpp
  src/ipc/handlers_code.cpp
  src/jobs.cpp
  src/health.cpp
  src/call.cpp
  src/call_invoke.asm
  src/call_dispatch.cpp
  src/alloc.cpp
  src/resolve.cpp
  src/locate.cpp
  src/discover.cpp
  src/place.cpp
  src/code.cpp
  src/pe_meta.cpp
  src/graph.cpp
  src/vtable.cpp
  src/watch.cpp
  src/disasm/registry.cpp
  src/disasm/zydis_backend.cpp
  src/disasm/capstone_backend.cpp
)

target_include_directories(hdllib
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(hdllib PRIVATE HDL_EXPORTS UNICODE _UNICODE)
target_compile_options(hdllib PRIVATE /W4 /EHsc /permissive-)
target_link_libraries(hdllib PRIVATE hdl_inject minhook)
set_target_properties(hdllib PROPERTIES OUTPUT_NAME hdllib)

# Stage beside the Python package so `pip install` / Scripts can find hdllib.dll.
set(HDL_PYTHON_NATIVE_DIR "${CMAKE_SOURCE_DIR}/python/hdllib/_native")
add_custom_command(TARGET hdllib POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "${HDL_PYTHON_NATIVE_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "$<TARGET_FILE:hdllib>"
    "${HDL_PYTHON_NATIVE_DIR}/hdllib.dll"
  COMMENT "Stage hdllib.dll into python/hdllib/_native for packaging"
)

if(HDL_DISASM_ZYDIS)
  target_compile_definitions(hdllib PRIVATE HDL_HAS_ZYDIS)
  target_link_libraries(hdllib PRIVATE Zydis)
endif()
if(HDL_DISASM_CAPSTONE)
  target_compile_definitions(hdllib PRIVATE HDL_HAS_CAPSTONE)
  if(TARGET capstone)
    target_link_libraries(hdllib PRIVATE capstone)
  elseif(TARGET capstone_static)
    target_link_libraries(hdllib PRIVATE capstone_static)
  else()
    target_link_libraries(hdllib PRIVATE capstone)
  endif()
endif()

if(HDL_BUILD_TOOLS)
  set(HDL_PDCURSES_OK FALSE)
  if(HDL_CLIENT_TUI)
    include(FetchContent)
    FetchContent_Declare(pdcurses
      GIT_REPOSITORY https://github.com/wmcbrine/PDCurses.git
      GIT_TAG 3.9
    )
    FetchContent_GetProperties(pdcurses)
    if(NOT pdcurses_POPULATED)
      FetchContent_Populate(pdcurses)
    endif()
    set(PDC_ROOT ${pdcurses_SOURCE_DIR})
    file(GLOB PDC_CORE_SOURCES CONFIGURE_DEPENDS "${PDC_ROOT}/pdcurses/*.c")
    set(PDC_WIN_SOURCES
      ${PDC_ROOT}/wincon/pdcclip.c
      ${PDC_ROOT}/wincon/pdcdisp.c
      ${PDC_ROOT}/wincon/pdcgetsc.c
      ${PDC_ROOT}/wincon/pdckbd.c
      ${PDC_ROOT}/wincon/pdcscrn.c
      ${PDC_ROOT}/wincon/pdcsetsc.c
      ${PDC_ROOT}/wincon/pdcutil.c
    )
    if(PDC_CORE_SOURCES AND EXISTS "${PDC_ROOT}/curses.h")
      add_library(pdcurses STATIC ${PDC_CORE_SOURCES} ${PDC_WIN_SOURCES})
      target_include_directories(pdcurses PUBLIC ${PDC_ROOT} ${PDC_ROOT}/wincon)
      target_compile_definitions(pdcurses PUBLIC PDC_WIDE UNICODE _UNICODE)
      if(MSVC)
        target_compile_options(pdcurses PRIVATE /W3)
      endif()
      set(HDL_PDCURSES_OK TRUE)
    else()
      message(WARNING "PDCurses sources not found; building hdlclient without --tui")
    endif()
  endif()

  add_executable(hdlclient
    tools/client/main.cpp
    tools/client/pipe_client.cpp
    tools/client/local_inject.cpp
    tools/client/usage.cpp
    tools/client/util.cpp
    tools/client/cmds_basic.cpp
    tools/client/cmds_call.cpp
    tools/client/cmds_hooks.cpp
    tools/client/cmds_locate.cpp
    tools/client/cmds_scan.cpp
    tools/client/cmds_discover.cpp
    tools/client/cmds_ipc_inject.cpp
    tools/client/cmds_place.cpp
    tools/client/ipc_ops.cpp
    tools/client/store.cpp
    tools/client/recipes.cpp
    tools/client/repl.cpp
    tools/client/tui.cpp
  )
  target_include_directories(hdlclient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/client
  )
  target_compile_definitions(hdlclient PRIVATE UNICODE _UNICODE)
  target_compile_options(hdlclient PRIVATE /W4 /EHsc /permissive-)
  target_link_libraries(hdlclient PRIVATE hdl_inject)
  if(HDL_PDCURSES_OK)
    target_compile_definitions(hdlclient PRIVATE HDL_HAS_TUI)
    target_link_libraries(hdlclient PRIVATE pdcurses user32 advapi32)
  endif()
endif()

if(HDL_BUILD_TESTS)
  enable_testing()

  add_executable(hdl_test_target tests/target/main.cpp)
  target_compile_definitions(hdl_test_target PRIVATE UNICODE _UNICODE)
  target_compile_options(hdl_test_target PRIVATE /W4 /EHsc /permissive-)
  target_link_libraries(hdl_test_target PRIVATE advapi32)

  add_executable(hdl_tests tests/test_main.cpp)
  target_include_directories(hdl_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(hdl_tests PRIVATE UNICODE _UNICODE)
  target_compile_options(hdl_tests PRIVATE /W4 /EHsc /permissive-)
  target_link_libraries(hdl_tests PRIVATE hdllib advapi32)
  add_dependencies(hdl_tests hdllib hdl_test_target)

  add_executable(hdl_select_tests tests/test_select.cpp)
  target_include_directories(hdl_select_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(hdl_select_tests PRIVATE UNICODE _UNICODE)
  target_compile_options(hdl_select_tests PRIVATE /W4 /EHsc /permissive-)
  target_link_libraries(hdl_select_tests PRIVATE hdl_inject)

  # Copy runtime deps next to the test exe (VS multi-config + Ninja).
  add_custom_command(TARGET hdl_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:hdllib> $<TARGET_FILE_DIR:hdl_tests>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:hdl_test_target> $<TARGET_FILE_DIR:hdl_tests>
    COMMENT "Copy hdllib.dll and hdl_test_target.exe beside hdl_tests"
  )

  add_test(NAME hdl_tests COMMAND hdl_tests WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_tests>)
  set_tests_properties(hdl_tests PROPERTIES TIMEOUT 600)
  add_test(NAME hdl_select_tests COMMAND hdl_select_tests)
  set_tests_properties(hdl_select_tests PROPERTIES TIMEOUT 60)

  add_executable(hdl_store_tests tests/store_test.cpp tools/client/store.cpp)
  target_include_directories(hdl_store_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/client
  )
  target_compile_definitions(hdl_store_tests PRIVATE UNICODE _UNICODE)
  target_compile_options(hdl_store_tests PRIVATE /W4 /EHsc /permissive-)
  add_test(NAME hdl_store_tests COMMAND hdl_store_tests)
  set_tests_properties(hdl_store_tests PROPERTIES TIMEOUT 30)

  if(HDL_BUILD_TOOLS)
    add_executable(hdl_client_tests tests/client_test_main.cpp tools/client/store.cpp)
    target_include_directories(hdl_client_tests PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/tools/client
      ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_compile_definitions(hdl_client_tests PRIVATE UNICODE _UNICODE)
    target_compile_options(hdl_client_tests PRIVATE /W4 /EHsc /permissive-)
    target_link_libraries(hdl_client_tests PRIVATE hdl_inject advapi32)
    add_dependencies(hdl_client_tests hdlclient hdllib hdl_test_target)
    add_custom_command(TARGET hdl_client_tests POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdllib> $<TARGET_FILE_DIR:hdl_client_tests>
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdl_test_target> $<TARGET_FILE_DIR:hdl_client_tests>
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdlclient> $<TARGET_FILE_DIR:hdl_client_tests>
      COMMENT "Copy hdllib, hdl_test_target, hdlclient beside hdl_client_tests"
    )
    add_test(NAME hdl_client_tests COMMAND hdl_client_tests WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_client_tests>)
    set_tests_properties(hdl_client_tests PROPERTIES TIMEOUT 300)
  endif()
endif()

if(HDL_BUILD_TOYS)
  add_executable(hdl_toy_arena toys/arena/main.cpp)
  target_compile_definitions(hdl_toy_arena PRIVATE UNICODE _UNICODE)
  target_compile_options(hdl_toy_arena PRIVATE /W4 /EHsc /permissive-)
  target_link_libraries(hdl_toy_arena PRIVATE advapi32)

  if(HDL_BUILD_TOOLS)
    add_executable(hdl_toy_tests tests/toy_test_main.cpp)
    target_include_directories(hdl_toy_tests PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_compile_definitions(hdl_toy_tests PRIVATE UNICODE _UNICODE)
    target_compile_options(hdl_toy_tests PRIVATE /W4 /EHsc /permissive-)
    target_link_libraries(hdl_toy_tests PRIVATE hdl_inject advapi32)
    add_dependencies(hdl_toy_tests hdlclient hdllib hdl_toy_arena)
    add_custom_command(TARGET hdl_toy_tests POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdllib> $<TARGET_FILE_DIR:hdl_toy_tests>
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdl_toy_arena> $<TARGET_FILE_DIR:hdl_toy_tests>
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdlclient> $<TARGET_FILE_DIR:hdl_toy_tests>
      COMMENT "Copy hdllib, hdl_toy_arena, hdlclient beside hdl_toy_tests"
    )
    add_test(NAME hdl_toy_tests COMMAND hdl_toy_tests WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_toy_tests>)
    set_tests_properties(hdl_toy_tests PROPERTIES TIMEOUT 180)
  endif()
endif()

install(TARGETS hdllib
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
install(DIRECTORY include/ DESTINATION include)
