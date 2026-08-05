cmake_minimum_required(VERSION 3.20)
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
option(HDL_DISASM_ZYDIS "Enable Zydis disasm backend" ON)
option(HDL_DISASM_CAPSTONE "Enable Capstone disasm backend" ON)
option(HDL_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" OFF)
option(HDL_ENABLE_ASAN "Enable AddressSanitizer for first-party targets" OFF)
option(HDL_ENABLE_CLANG_TIDY "Run clang-tidy while compiling first-party C++ targets" OFF)
option(HDL_ENABLE_MSVC_ANALYZE "Enable MSVC native code analysis for first-party targets" OFF)
option(HDL_BUILD_FUZZERS "Build clang-cl/libFuzzer parser harnesses" OFF)
option(HDL_ENABLE_COVERAGE "Enable clang source-based coverage for first-party targets" OFF)

if((HDL_BUILD_FUZZERS OR HDL_ENABLE_COVERAGE) AND
    NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "HDL_BUILD_FUZZERS and HDL_ENABLE_COVERAGE require clang-cl")
endif()
if(HDL_BUILD_FUZZERS AND HDL_ENABLE_COVERAGE)
  message(FATAL_ERROR "Fuzzing and coverage use separate build presets")
endif()

if(HDL_BUILD_FUZZERS)
  add_compile_definitions(
    _DISABLE_STRING_ANNOTATION
    _DISABLE_VECTOR_ANNOTATION
    _DISABLE_OPTIONAL_ANNOTATION)
  execute_process(
    COMMAND "${CMAKE_CXX_COMPILER}" --print-resource-dir
    RESULT_VARIABLE _HDL_CLANG_RESOURCE_RESULT
    OUTPUT_VARIABLE HDL_CLANG_RESOURCE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _HDL_CLANG_RESOURCE_RESULT EQUAL 0 OR
      NOT IS_DIRECTORY "${HDL_CLANG_RESOURCE_DIR}/lib/windows")
    message(FATAL_ERROR "Unable to locate the clang-cl runtime directory")
  endif()
  set(HDL_CLANG_RUNTIME_DIR "${HDL_CLANG_RESOURCE_DIR}/lib/windows")
  unset(_HDL_CLANG_RESOURCE_RESULT)
endif()

if(HDL_ENABLE_CLANG_TIDY)
  find_program(HDL_CLANG_TIDY_EXECUTABLE NAMES clang-tidy REQUIRED)
endif()

function(hdl_configure_target target_name)
  set(_HDL_TARGET_OPTIONS HOST_TOOL)
  cmake_parse_arguments(HDL_TARGET "${_HDL_TARGET_OPTIONS}" "" "" ${ARGN})

  target_compile_options(${target_name} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:/W4>"
    "$<$<COMPILE_LANGUAGE:CXX>:/W4;/EHsc;/permissive->")

  if(HDL_WARNINGS_AS_ERRORS)
    target_compile_options(${target_name} PRIVATE
      "$<$<COMPILE_LANGUAGE:C,CXX>:/WX>")
  endif()

  # Build-time host tools link against uninstrumented dependency libraries, so
  # keep sanitizer and coverage instrumentation off those executables.
  if(HDL_ENABLE_ASAN AND NOT HDL_TARGET_HOST_TOOL)
    if(NOT MSVC)
      message(FATAL_ERROR "HDL_ENABLE_ASAN currently requires the Microsoft C++ compiler")
    endif()

    target_compile_options(${target_name} PRIVATE
      "$<$<COMPILE_LANGUAGE:C,CXX>:/fsanitize=address;/Zi>")

    get_target_property(hdl_target_type ${target_name} TYPE)
    if(hdl_target_type STREQUAL "EXECUTABLE"
        OR hdl_target_type STREQUAL "SHARED_LIBRARY"
        OR hdl_target_type STREQUAL "MODULE_LIBRARY")
      target_link_options(${target_name} PRIVATE /INCREMENTAL:NO)
    endif()
  endif()

  if(HDL_ENABLE_MSVC_ANALYZE)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
      message(FATAL_ERROR "HDL_ENABLE_MSVC_ANALYZE requires the Microsoft C++ compiler")
    endif()

    # Raw target-memory and dynamic-call boundaries intentionally use SEH
    # catch-all filters to translate faults into API errors. C6320 flags that
    # deliberate boundary, so suppress only that diagnostic for /analyze.
    target_compile_options(${target_name} PRIVATE
      "$<$<COMPILE_LANGUAGE:C,CXX>:/analyze;/wd6320>")
  endif()

  if(HDL_ENABLE_CLANG_TIDY)
    set_property(TARGET ${target_name} PROPERTY CXX_CLANG_TIDY
      "${HDL_CLANG_TIDY_EXECUTABLE};--quiet")
  endif()

  if(HDL_BUILD_FUZZERS AND NOT HDL_TARGET_HOST_TOOL)
    target_compile_options(${target_name} PRIVATE
      "$<$<COMPILE_LANGUAGE:C,CXX>:-fsanitize=fuzzer-no-link,address>")
  endif()

  if(HDL_ENABLE_COVERAGE AND NOT HDL_TARGET_HOST_TOOL)
    target_compile_options(${target_name} PRIVATE
      "$<$<COMPILE_LANGUAGE:C,CXX>:-fprofile-instr-generate;-fcoverage-mapping>")
    get_target_property(hdl_target_type ${target_name} TYPE)
    if(hdl_target_type STREQUAL "EXECUTABLE"
        OR hdl_target_type STREQUAL "SHARED_LIBRARY"
        OR hdl_target_type STREQUAL "MODULE_LIBRARY")
      target_link_options(${target_name} PRIVATE
        -fprofile-instr-generate
        /INCREMENTAL:NO)
    endif()
  endif()

  unset(_HDL_TARGET_OPTIONS)
endfunction()

function(hdl_configure_fuzzer target_name)
  hdl_configure_target(${target_name})
  target_compile_options(${target_name} PRIVATE
    "$<$<COMPILE_LANGUAGE:C,CXX>:-fsanitize=fuzzer,address>")
  set(_HDL_FUZZER_RUNTIME
    "${HDL_CLANG_RUNTIME_DIR}/clang_rt.fuzzer-x86_64.lib")
  set(_HDL_ASAN_RUNTIME
    "${HDL_CLANG_RUNTIME_DIR}/clang_rt.asan_dynamic-x86_64.lib")
  set(_HDL_ASAN_THUNK
    "${HDL_CLANG_RUNTIME_DIR}/clang_rt.asan_static_runtime_thunk-x86_64.lib")
  set(_HDL_ASAN_DLL
    "${HDL_CLANG_RUNTIME_DIR}/clang_rt.asan_dynamic-x86_64.dll")
  foreach(_HDL_RUNTIME IN ITEMS
      "${_HDL_FUZZER_RUNTIME}" "${_HDL_ASAN_RUNTIME}"
      "${_HDL_ASAN_THUNK}" "${_HDL_ASAN_DLL}")
    if(NOT EXISTS "${_HDL_RUNTIME}")
      message(FATAL_ERROR "Required clang runtime not found: ${_HDL_RUNTIME}")
    endif()
  endforeach()
  target_link_libraries(${target_name} PRIVATE "${_HDL_ASAN_RUNTIME}")
  target_link_options(${target_name} PRIVATE
    "/WHOLEARCHIVE:${_HDL_FUZZER_RUNTIME}"
    "/WHOLEARCHIVE:${_HDL_ASAN_THUNK}"
    /INCREMENTAL:NO)
  add_custom_command(TARGET ${target_name} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${_HDL_ASAN_DLL}" "$<TARGET_FILE_DIR:${target_name}>")
  unset(_HDL_FUZZER_RUNTIME)
  unset(_HDL_ASAN_RUNTIME)
  unset(_HDL_ASAN_THUNK)
  unset(_HDL_ASAN_DLL)
  unset(_HDL_RUNTIME)
endfunction()

if(NOT HDL_DISASM_ZYDIS AND NOT HDL_DISASM_CAPSTONE)
  message(FATAL_ERROR "At least one of HDL_DISASM_ZYDIS or HDL_DISASM_CAPSTONE must be ON")
endif()

# Current CMake releases no longer accept policy compatibility below 3.5.
# Use the CMake 3.13 policy set so vendored option() calls honor normal
# variables (CMP0077). Keep the override scoped to third-party projects;
# first-party code retains this project's own CMake 3.20 policy contract.
if(DEFINED CMAKE_POLICY_VERSION_MINIMUM)
  set(_HDL_SAVED_CMAKE_POLICY_VERSION_MINIMUM "${CMAKE_POLICY_VERSION_MINIMUM}")
  set(_HDL_CMAKE_POLICY_VERSION_MINIMUM_WAS_DEFINED TRUE)
else()
  set(_HDL_CMAKE_POLICY_VERSION_MINIMUM_WAS_DEFINED FALSE)
endif()
set(CMAKE_POLICY_VERSION_MINIMUM 3.13)

include(FetchContent)

if(HDL_DISASM_ZYDIS)
  set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
  set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    # v4.1.1
    GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc
  )
  FetchContent_MakeAvailable(zydis)
  # Zycore exports an MSVC-only warning suppression without a language guard.
  # Keep it from reaching MASM sources, where ml64 reports it as invalid.
  foreach(_HDL_ZYDIS_TARGET IN ITEMS Zycore Zydis)
    if(NOT TARGET ${_HDL_ZYDIS_TARGET})
      continue()
    endif()
    get_target_property(_HDL_ZYDIS_INTERFACE_OPTIONS
      ${_HDL_ZYDIS_TARGET} INTERFACE_COMPILE_OPTIONS)
    if(_HDL_ZYDIS_INTERFACE_OPTIONS)
      list(REMOVE_ITEM _HDL_ZYDIS_INTERFACE_OPTIONS "/wd4201")
      list(APPEND _HDL_ZYDIS_INTERFACE_OPTIONS
        "$<$<COMPILE_LANGUAGE:C,CXX>:/wd4201>")
      set_property(TARGET ${_HDL_ZYDIS_TARGET} PROPERTY INTERFACE_COMPILE_OPTIONS
        "${_HDL_ZYDIS_INTERFACE_OPTIONS}")
    endif()
  endforeach()
  unset(_HDL_ZYDIS_INTERFACE_OPTIONS)
  unset(_HDL_ZYDIS_TARGET)
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
    # 5.0.3
    GIT_TAG 5cca00533dadfe53181f1de3525f859769f69b65
  )
  FetchContent_MakeAvailable(capstone)
endif()

# First-release named RPC schema/runtime.  Pin the release commit rather than a
# mutable tag so DependencyPins and OfflineBuild can reproduce it exactly.
FetchContent_Declare(absl
  # 20250512.1, commit 76bb24329e8bf5f39704eb10d21b9a80befa7c81.
  URL https://github.com/abseil/abseil-cpp/archive/76bb24329e8bf5f39704eb10d21b9a80befa7c81.zip
  URL_HASH SHA256=8c5dffb59465aed858fd8f9c1207f5963a8f9ada8d39cc15877f762c7b444560
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
set(ABSL_MSVC_STATIC_RUNTIME ${HDL_BUILD_FUZZERS} CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(absl)

set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_PROTOC_BINARIES ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_LIBPROTOC ON CACHE BOOL "" FORCE)
# The fuzz preset intentionally uses the static MSVC CRT. Generated messages,
# Protobuf itself, and every final fuzz executable must agree on that choice.
set(protobuf_MSVC_STATIC_RUNTIME ${HDL_BUILD_FUZZERS} CACHE BOOL "" FORCE)
set(protobuf_WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(protobuf_INSTALL OFF CACHE BOOL "" FORCE)
set(utf8_range_ENABLE_TESTS OFF CACHE BOOL "" FORCE)
set(utf8_range_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(protobuf
  # Official v35.0 release archive for commit
  # e59364c38e10de3686a3305ff11fbfc59a10dbd8.
  URL https://github.com/protocolbuffers/protobuf/releases/download/v35.0/protobuf-35.0.zip
  URL_HASH SHA256=20f10bb6ba69c391add381310d10747d4b0c32660ad651932ffcb9d04b748845
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(protobuf)

# Vendored MinHook v1.3.4, upstream commit c3fcafdc10146beb5919319d0683e44e3c30d537.
# Its upstream CMake package metadata still reports 1.3.3; the source tag is authoritative.
if(DEFINED BUILD_SHARED_LIBS)
  set(_HDL_SAVED_BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS}")
  set(_HDL_BUILD_SHARED_LIBS_WAS_DEFINED TRUE)
else()
  set(_HDL_BUILD_SHARED_LIBS_WAS_DEFINED FALSE)
endif()
set(BUILD_SHARED_LIBS OFF)
add_subdirectory(third_party/minhook EXCLUDE_FROM_ALL)
if(_HDL_BUILD_SHARED_LIBS_WAS_DEFINED)
  set(BUILD_SHARED_LIBS "${_HDL_SAVED_BUILD_SHARED_LIBS}")
else()
  unset(BUILD_SHARED_LIBS)
endif()
unset(_HDL_SAVED_BUILD_SHARED_LIBS)
unset(_HDL_BUILD_SHARED_LIBS_WAS_DEFINED)
if(_HDL_CMAKE_POLICY_VERSION_MINIMUM_WAS_DEFINED)
  set(CMAKE_POLICY_VERSION_MINIMUM "${_HDL_SAVED_CMAKE_POLICY_VERSION_MINIMUM}")
else()
  unset(CMAKE_POLICY_VERSION_MINIMUM)
endif()
unset(_HDL_SAVED_CMAKE_POLICY_VERSION_MINIMUM)
unset(_HDL_CMAKE_POLICY_VERSION_MINIMUM_WAS_DEFINED)

set(HDL_RPC_PROTO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(HDL_RPC_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(HDL_RPC_PROTOBUF_SYSTEM_INCLUDE_DIRS
  "${protobuf_SOURCE_DIR}"
  "${protobuf_SOURCE_DIR}/upb/reflection/cmake"
  "${absl_SOURCE_DIR}"
  "${protobuf_SOURCE_DIR}/src"
  "${protobuf_SOURCE_DIR}/third_party/utf8_range")
set(HDL_RPC_PROTO_FILES
  "${HDL_RPC_PROTO_ROOT}/hdl/rpc/v1/common.proto"
  "${HDL_RPC_PROTO_ROOT}/hdl/rpc/v1/envelope.proto"
  "${HDL_RPC_PROTO_ROOT}/hdl/rpc/v1/services.proto")
set(HDL_RPC_PROTO_SOURCES
  "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1/common.pb.cc"
  "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1/envelope.pb.cc"
  "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1/services.pb.cc")
set(HDL_RPC_PROTO_HEADERS
  "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1/common.pb.h"
  "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1/envelope.pb.h"
  "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1/services.pb.h")
set(HDL_RPC_BINDING_OUTPUTS
  "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1/services.rpc.hpp"
  "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1/services.rpc.dispatch.inc")

add_executable(hdl_rpc_codegen tools/rpc_codegen/main.cpp)
target_link_libraries(hdl_rpc_codegen PRIVATE protobuf::libprotoc protobuf::libprotobuf)
target_include_directories(hdl_rpc_codegen SYSTEM PRIVATE
  ${HDL_RPC_PROTOBUF_SYSTEM_INCLUDE_DIRS})
hdl_configure_target(hdl_rpc_codegen HOST_TOOL)
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  # MSVC 14.51 reports C4702 from Abseil template expansion even when its
  # include roots are external; keep that dependency diagnostic out of /WX.
  target_compile_options(hdl_rpc_codegen PRIVATE /wd4702)
endif()

add_custom_command(
  OUTPUT ${HDL_RPC_PROTO_SOURCES} ${HDL_RPC_PROTO_HEADERS}
  COMMAND ${CMAKE_COMMAND} -E make_directory "${HDL_RPC_GENERATED_DIR}"
  COMMAND $<TARGET_FILE:protobuf::protoc>
    --proto_path=${HDL_RPC_PROTO_ROOT}
    --cpp_out=${HDL_RPC_GENERATED_DIR}
    ${HDL_RPC_PROTO_FILES}
  DEPENDS protobuf::protoc ${HDL_RPC_PROTO_FILES}
  VERBATIM
  COMMENT "Generating hdllib Protobuf Lite messages")

add_custom_command(
  OUTPUT ${HDL_RPC_BINDING_OUTPUTS}
  COMMAND ${CMAKE_COMMAND} -E make_directory
    "${HDL_RPC_GENERATED_DIR}/hdl/rpc/v1"
  COMMAND $<TARGET_FILE:protobuf::protoc>
    --proto_path=${HDL_RPC_PROTO_ROOT}
    --plugin=protoc-gen-hdl_rpc=$<TARGET_FILE:hdl_rpc_codegen>
    --hdl_rpc_out=${HDL_RPC_GENERATED_DIR}
    ${HDL_RPC_PROTO_ROOT}/hdl/rpc/v1/services.proto
  DEPENDS protobuf::protoc hdl_rpc_codegen ${HDL_RPC_PROTO_FILES}
  VERBATIM
  COMMENT "Generating hdllib named RPC bindings")

add_custom_target(hdl_rpc_generated
  DEPENDS ${HDL_RPC_PROTO_SOURCES} ${HDL_RPC_PROTO_HEADERS} ${HDL_RPC_BINDING_OUTPUTS})

add_library(hdl_rpc_proto STATIC ${HDL_RPC_PROTO_SOURCES} ${HDL_RPC_PROTO_HEADERS})
add_dependencies(hdl_rpc_proto hdl_rpc_generated)
target_include_directories(hdl_rpc_proto PUBLIC
  "${HDL_RPC_GENERATED_DIR}")
target_include_directories(hdl_rpc_proto SYSTEM PUBLIC
  ${HDL_RPC_PROTOBUF_SYSTEM_INCLUDE_DIRS})
target_link_libraries(hdl_rpc_proto PUBLIC protobuf::libprotobuf-lite)

add_library(hdl_rpc_runtime STATIC
  src/rpc/runtime.cpp
  src/ipc/framing.cpp)
add_dependencies(hdl_rpc_runtime hdl_rpc_generated)
target_include_directories(hdl_rpc_runtime
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${HDL_RPC_GENERATED_DIR})
target_compile_definitions(hdl_rpc_runtime PRIVATE UNICODE _UNICODE)
hdl_configure_target(hdl_rpc_runtime)
target_link_libraries(hdl_rpc_runtime PUBLIC hdl_rpc_proto advapi32 bcrypt)

set(HDL_INJECT_SOURCES
  src/inject.cpp
  src/inject/common.cpp
  src/inject/select.cpp
  src/inject/create_remote_thread.cpp
  src/inject/unload.cpp
  src/inject/nt_create_thread_ex.cpp
  src/inject/rtl_create_user_thread.cpp
  src/inject/queue_user_apc.cpp
  src/inject/set_windows_hook_ex.cpp
  src/inject/thread_hijack.cpp
  src/inject/manual_map.cpp
  src/inject/pe_image_view.cpp
  src/inject/pe_relocs.cpp
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
    ${HDL_RPC_GENERATED_DIR}
)
add_dependencies(hdl_inject hdl_rpc_generated)
target_compile_definitions(hdl_inject PRIVATE UNICODE _UNICODE)
hdl_configure_target(hdl_inject)
target_link_libraries(hdl_inject PUBLIC Psapi Advapi32 PRIVATE hdl_rpc_runtime)

set(HDL_DOMAIN_SOURCES
  src/core.cpp
  src/loaded_modules.cpp
  src/memory_rw.cpp
  src/memory_aob.cpp
  src/memory_search.cpp
  src/hooks.cpp
  src/hooks_trace.asm
  src/ipc_server.cpp
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
  src/fingerprint.cpp
  src/call.cpp
  src/call_invoke.asm
  src/call_dispatch.cpp
  src/alloc.cpp
  src/resolve.cpp
  src/locate.cpp
  src/discover_session.cpp
  src/discover_scan.cpp
  src/discover_path.cpp
  src/discover_watch.cpp
  src/discover_type.cpp
  src/discover_serde.cpp
  src/json/json.cpp
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

# Shared domain objects: linked into hdllib.dll and into in-process domain tests.
add_library(hdl_domain_obj OBJECT ${HDL_DOMAIN_SOURCES})
target_include_directories(hdl_domain_obj
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${HDL_RPC_GENERATED_DIR}
)
add_dependencies(hdl_domain_obj hdl_rpc_generated)
target_compile_definitions(hdl_domain_obj PRIVATE UNICODE _UNICODE)
hdl_configure_target(hdl_domain_obj)
target_link_libraries(hdl_domain_obj PUBLIC hdl_inject minhook hdl_rpc_runtime)

add_library(hdllib SHARED
  src/dllmain.cpp
  src/api.cpp
  $<TARGET_OBJECTS:hdl_domain_obj>
)

target_include_directories(hdllib
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(hdllib PRIVATE HDL_EXPORTS UNICODE _UNICODE)
hdl_configure_target(hdllib)
target_link_libraries(hdllib PRIVATE hdl_inject minhook hdl_rpc_runtime)
set_target_properties(hdllib PROPERTIES OUTPUT_NAME hdllib)

if(HDL_DISASM_ZYDIS)
  target_compile_definitions(hdl_domain_obj PRIVATE HDL_HAS_ZYDIS)
  target_compile_definitions(hdllib PRIVATE HDL_HAS_ZYDIS)
  target_link_libraries(hdl_domain_obj PUBLIC Zydis)
  target_link_libraries(hdllib PRIVATE Zydis)
endif()
if(HDL_DISASM_CAPSTONE)
  target_compile_definitions(hdl_domain_obj PRIVATE HDL_HAS_CAPSTONE)
  target_compile_definitions(hdllib PRIVATE HDL_HAS_CAPSTONE)
  if(TARGET capstone)
    target_link_libraries(hdl_domain_obj PUBLIC capstone)
    target_link_libraries(hdllib PRIVATE capstone)
  elseif(TARGET capstone_static)
    target_link_libraries(hdl_domain_obj PUBLIC capstone_static)
    target_link_libraries(hdllib PRIVATE capstone_static)
  else()
    target_link_libraries(hdl_domain_obj PUBLIC capstone)
    target_link_libraries(hdllib PRIVATE capstone)
  endif()
endif()

if(HDL_BUILD_FUZZERS)
  add_executable(hdl_fuzz_ipc tests/fuzz/fuzz_ipc.cpp)
  target_include_directories(hdl_fuzz_ipc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${HDL_RPC_GENERATED_DIR})
  add_dependencies(hdl_fuzz_ipc hdl_rpc_generated)
  target_link_libraries(hdl_fuzz_ipc PRIVATE hdl_rpc_proto)
  hdl_configure_fuzzer(hdl_fuzz_ipc)

  add_executable(hdl_fuzz_search
    tests/fuzz/fuzz_search.cpp
    $<TARGET_OBJECTS:hdl_domain_obj>)
  target_include_directories(hdl_fuzz_search PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(hdl_fuzz_search PRIVATE HDL_DOMAIN_TESTS UNICODE _UNICODE)
  hdl_configure_fuzzer(hdl_fuzz_search)
  target_link_libraries(hdl_fuzz_search PRIVATE hdl_inject minhook hdl_rpc_runtime advapi32)

  add_executable(hdl_fuzz_pe
    tests/fuzz/fuzz_pe.cpp
    src/inject/pe_image_view.cpp
    src/inject/pe_relocs.cpp)
  target_include_directories(hdl_fuzz_pe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(hdl_fuzz_pe PRIVATE UNICODE _UNICODE)
  hdl_configure_fuzzer(hdl_fuzz_pe)

  add_executable(hdl_fuzz_json
    tests/fuzz/fuzz_json.cpp
    tools/client/store.cpp
    $<TARGET_OBJECTS:hdl_domain_obj>)
  target_include_directories(hdl_fuzz_json PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/client)
  target_compile_definitions(hdl_fuzz_json PRIVATE HDL_DOMAIN_TESTS UNICODE _UNICODE)
  hdl_configure_fuzzer(hdl_fuzz_json)
  target_link_libraries(hdl_fuzz_json PRIVATE hdl_inject minhook hdl_rpc_runtime advapi32)

  add_executable(hdl_fuzz_invocation
    tests/fuzz/fuzz_invocation.cpp
    tools/client/invocation.cpp)
  target_include_directories(hdl_fuzz_invocation PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/client)
  target_compile_definitions(hdl_fuzz_invocation PRIVATE UNICODE _UNICODE)
  hdl_configure_fuzzer(hdl_fuzz_invocation)

  foreach(_hdl_domain_fuzzer hdl_fuzz_search hdl_fuzz_json)
    if(HDL_DISASM_ZYDIS)
      target_compile_definitions(${_hdl_domain_fuzzer} PRIVATE HDL_HAS_ZYDIS)
      target_link_libraries(${_hdl_domain_fuzzer} PRIVATE Zydis)
    endif()
    if(HDL_DISASM_CAPSTONE)
      target_compile_definitions(${_hdl_domain_fuzzer} PRIVATE HDL_HAS_CAPSTONE)
      if(TARGET capstone)
        target_link_libraries(${_hdl_domain_fuzzer} PRIVATE capstone)
      elseif(TARGET capstone_static)
        target_link_libraries(${_hdl_domain_fuzzer} PRIVATE capstone_static)
      endif()
    endif()
  endforeach()
endif()

if(HDL_BUILD_TOOLS)
  add_executable(hdlclient
    tools/client/main.cpp
    tools/client/invocation.cpp
    tools/client/pipe_client.cpp
    tools/client/local_inject.cpp
    tools/client/session_modules.cpp
    tools/client/session_persist.cpp
    tools/client/usage.cpp
    tools/client/util.cpp
    tools/client/json_out.cpp
    tools/client/cmds_basic.cpp
    tools/client/cmds_call.cpp
    tools/client/cmds_hooks.cpp
    tools/client/cmds_locate.cpp
    tools/client/cmds_scan.cpp
    tools/client/cmds_discover.cpp
    tools/client/cmds_controller.cpp
    tools/client/cmds_ipc_inject.cpp
    tools/client/cmds_place_mem.cpp
    tools/client/cmds_disasm.cpp
    tools/client/cmds_pe_meta.cpp
    tools/client/cmds_typeinfo.cpp
    tools/client/cmds_watch.cpp
    tools/client/cmds_patch.cpp
    tools/client/ipc_ops.cpp
    tools/client/store.cpp
    tools/client/recipes.cpp
    src/json/json.cpp
  )
  target_include_directories(hdlclient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/client
    ${HDL_RPC_GENERATED_DIR}
  )
  add_dependencies(hdlclient hdl_rpc_generated)
  target_compile_definitions(hdlclient PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdlclient)
  target_link_libraries(hdlclient PRIVATE hdl_inject hdl_rpc_runtime user32 advapi32)
endif()

if(HDL_BUILD_TESTS)
  enable_testing()

  add_executable(hdl_test_target tests/target/main.cpp)
  target_compile_definitions(hdl_test_target PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdl_test_target)
  target_link_libraries(hdl_test_target PRIVATE advapi32)

  add_executable(hdl_tests
    tests/test_main.cpp
    tests/test_fixtures.cpp
    tests/test_local_api.cpp
    tests/test_locate.cpp
    tests/test_discover_target.cpp
    tests/test_lifecycle.cpp
    tests/test_inject_matrix.cpp
    $<TARGET_OBJECTS:hdl_domain_obj>
  )
  target_include_directories(hdl_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(hdl_tests PRIVATE UNICODE _UNICODE HDL_DOMAIN_TESTS)
  hdl_configure_target(hdl_tests)
  target_link_libraries(hdl_tests PRIVATE hdl_inject minhook hdl_rpc_runtime advapi32)
  if(HDL_DISASM_ZYDIS)
    target_compile_definitions(hdl_tests PRIVATE HDL_HAS_ZYDIS)
    target_link_libraries(hdl_tests PRIVATE Zydis)
  endif()
  if(HDL_DISASM_CAPSTONE)
    target_compile_definitions(hdl_tests PRIVATE HDL_HAS_CAPSTONE)
    if(TARGET capstone)
      target_link_libraries(hdl_tests PRIVATE capstone)
    elseif(TARGET capstone_static)
      target_link_libraries(hdl_tests PRIVATE capstone_static)
    else()
      target_link_libraries(hdl_tests PRIVATE capstone)
    endif()
  endif()
  add_dependencies(hdl_tests hdllib hdl_test_target)

  add_executable(hdl_select_tests tests/test_select.cpp)
  target_include_directories(hdl_select_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(hdl_select_tests PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdl_select_tests)
  target_link_libraries(hdl_select_tests PRIVATE hdl_inject)

  # Copy runtime deps next to the test exe (VS multi-config + Ninja).
  add_custom_command(TARGET hdl_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:hdllib> $<TARGET_FILE_DIR:hdl_tests>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:hdl_test_target> $<TARGET_FILE_DIR:hdl_tests>
    COMMENT "Copy hdllib.dll and hdl_test_target.exe beside hdl_tests"
  )

  add_test(NAME hdl_api_tests
    COMMAND hdl_tests --api-only
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_tests>)
  set_tests_properties(hdl_api_tests PROPERTIES
    TIMEOUT 300
    LABELS "api;gui"
    RESOURCE_LOCK hdl_gui_desktop)

  add_test(NAME hdl_api_headless_tests
    COMMAND hdl_tests --api-headless-only
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_tests>)
  set_tests_properties(hdl_api_headless_tests PROPERTIES
    TIMEOUT 300
    LABELS "api;headless")

  add_test(NAME hdl_api_asan_tests
    COMMAND hdl_tests --api-asan-only
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_tests>)
  set_tests_properties(hdl_api_asan_tests PROPERTIES
    TIMEOUT 300
    LABELS "api;asan"
    RESOURCE_LOCK hdl_gui_desktop)

  add_test(NAME hdl_locate_tests
    COMMAND hdl_tests --locate-only
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_tests>)
  set_tests_properties(hdl_locate_tests PROPERTIES
    TIMEOUT 300
    LABELS "gui;locate"
    RESOURCE_LOCK hdl_gui_desktop)

  add_test(NAME hdl_inject_tests
    COMMAND hdl_tests --inject-only
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_tests>)
  set_tests_properties(hdl_inject_tests PROPERTIES
    TIMEOUT 600
    LABELS "gui;inject"
    RESOURCE_LOCK hdl_gui_desktop)

  add_test(NAME hdl_lifecycle_tests
    COMMAND hdl_tests --lifecycle-only
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_tests>)
  set_tests_properties(hdl_lifecycle_tests PROPERTIES
    TIMEOUT 600
    LABELS "lifecycle;gui"
    RESOURCE_LOCK hdl_gui_desktop)

  add_test(NAME hdl_tests
    COMMAND hdl_tests
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_tests>)
  set_tests_properties(hdl_tests PROPERTIES
    TIMEOUT 900
    LABELS "full;gui"
    RESOURCE_LOCK hdl_gui_desktop)

  add_test(NAME hdl_select_tests COMMAND hdl_select_tests)
  set_tests_properties(hdl_select_tests PROPERTIES
    TIMEOUT 60
    LABELS "headless;unit")

  add_executable(hdl_store_tests tests/store_test.cpp tools/client/store.cpp src/json/json.cpp)
  target_include_directories(hdl_store_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/client
  )
  target_compile_definitions(hdl_store_tests PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdl_store_tests)
  add_test(NAME hdl_store_tests COMMAND hdl_store_tests)
  set_tests_properties(hdl_store_tests PROPERTIES
    TIMEOUT 30
    LABELS "headless;unit")

  add_executable(hdl_pe_tests
    tests/pe_image_test.cpp
    src/inject/pe_image_view.cpp
    src/inject/pe_relocs.cpp
  )
  target_include_directories(hdl_pe_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${HDL_RPC_GENERATED_DIR}
  )
  add_dependencies(hdl_pe_tests hdl_rpc_generated)
  target_compile_definitions(hdl_pe_tests PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdl_pe_tests)
  target_link_libraries(hdl_pe_tests PRIVATE hdl_rpc_runtime)
  add_test(NAME hdl_pe_tests COMMAND hdl_pe_tests)
  set_tests_properties(hdl_pe_tests PROPERTIES
    TIMEOUT 30
    LABELS "headless;unit")

  add_executable(hdl_json_tests tests/json_test.cpp src/json/json.cpp)
  target_include_directories(hdl_json_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_definitions(hdl_json_tests PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdl_json_tests)
  add_test(NAME hdl_json_tests COMMAND hdl_json_tests)
  set_tests_properties(hdl_json_tests PROPERTIES
    TIMEOUT 30
    LABELS "headless;unit")

  add_executable(hdl_invocation_tests
    tests/invocation_test.cpp
    tools/client/invocation.cpp
  )
  target_include_directories(hdl_invocation_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/client
  )
  target_compile_definitions(hdl_invocation_tests PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdl_invocation_tests)
  add_test(NAME hdl_invocation_tests COMMAND hdl_invocation_tests)
  set_tests_properties(hdl_invocation_tests PROPERTIES
    TIMEOUT 30
    LABELS "headless;unit;client")

  add_executable(hdl_rpc_schema_tests tests/rpc_schema_test.cpp)
  target_include_directories(hdl_rpc_schema_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${HDL_RPC_GENERATED_DIR}
  )
  string(REPLACE "\\" "/" _hdl_handlers_hpp "${CMAKE_CURRENT_SOURCE_DIR}/src/ipc/handlers.hpp")
  target_compile_definitions(hdl_rpc_schema_tests PRIVATE
    UNICODE _UNICODE
    "HDL_HANDLERS_HPP=\"${_hdl_handlers_hpp}\"")
  add_dependencies(hdl_rpc_schema_tests hdl_rpc_generated)
  hdl_configure_target(hdl_rpc_schema_tests)
  add_test(NAME hdl_rpc_schema_tests COMMAND hdl_rpc_schema_tests)
  set_tests_properties(hdl_rpc_schema_tests PROPERTIES
    TIMEOUT 30
    LABELS "headless;unit")

  add_executable(hdl_abi_tests tests/abi_layout_test.cpp)
  target_include_directories(hdl_abi_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  )
  target_compile_definitions(hdl_abi_tests PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdl_abi_tests)
  add_dependencies(hdl_abi_tests hdllib)
  add_custom_command(TARGET hdl_abi_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:hdllib> $<TARGET_FILE_DIR:hdl_abi_tests>
    COMMAND ${CMAKE_COMMAND} -E copy_directory
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/golden
      $<TARGET_FILE_DIR:hdl_abi_tests>/golden
    COMMENT "Copy hdllib.dll and golden test data beside hdl_abi_tests"
  )
  add_test(NAME hdl_abi_tests
    COMMAND hdl_abi_tests
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_abi_tests>)
  set_tests_properties(hdl_abi_tests PROPERTIES
    TIMEOUT 30
    LABELS "headless;abi;unit")

  if(HDL_BUILD_TOOLS)
    add_executable(hdl_client_tests
      tests/client_test_main.cpp
      tools/client/store.cpp
      tools/client/pipe_client.cpp
      src/json/json.cpp
    )
    target_include_directories(hdl_client_tests PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src
      ${CMAKE_CURRENT_SOURCE_DIR}/tools/client
      ${CMAKE_CURRENT_SOURCE_DIR}/tests
      ${HDL_RPC_GENERATED_DIR}
    )
    add_dependencies(hdl_client_tests hdl_rpc_generated)
    target_compile_definitions(hdl_client_tests PRIVATE UNICODE _UNICODE)
    if(HDL_DISASM_ZYDIS)
      target_compile_definitions(hdl_client_tests PRIVATE HDL_HAS_ZYDIS)
    endif()
    if(HDL_DISASM_CAPSTONE)
      target_compile_definitions(hdl_client_tests PRIVATE HDL_HAS_CAPSTONE)
    endif()
    hdl_configure_target(hdl_client_tests)
    target_link_libraries(hdl_client_tests PRIVATE hdl_inject hdl_rpc_runtime advapi32)
    add_dependencies(hdl_client_tests hdlclient hdllib hdl_test_target)
    add_custom_command(TARGET hdl_client_tests POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdllib> $<TARGET_FILE_DIR:hdl_client_tests>
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdl_test_target> $<TARGET_FILE_DIR:hdl_client_tests>
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hdlclient> $<TARGET_FILE_DIR:hdl_client_tests>
      COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/golden
        $<TARGET_FILE_DIR:hdl_client_tests>/golden
      COMMENT "Copy hdllib, hdl_test_target, hdlclient, golden beside hdl_client_tests"
    )
    add_test(NAME hdl_client_tests
      COMMAND hdl_client_tests
      WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_client_tests>)
    set_tests_properties(hdl_client_tests PROPERTIES
      TIMEOUT 300
      LABELS "client;headless;ipc")
  endif()
endif()

if(HDL_BUILD_TOYS)
  add_executable(hdl_toy_arena toys/arena/main.cpp)
  target_compile_definitions(hdl_toy_arena PRIVATE UNICODE _UNICODE)
  hdl_configure_target(hdl_toy_arena)
  target_link_libraries(hdl_toy_arena PRIVATE advapi32)

  if(HDL_BUILD_TOOLS)
    add_executable(hdl_toy_tests tests/toy_test_main.cpp)
    target_include_directories(hdl_toy_tests PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_compile_definitions(hdl_toy_tests PRIVATE UNICODE _UNICODE)
    hdl_configure_target(hdl_toy_tests)
    target_link_libraries(hdl_toy_tests PRIVATE hdl_inject hdl_rpc_runtime advapi32)
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
    add_test(NAME hdl_toy_tests
      COMMAND hdl_toy_tests
      WORKING_DIRECTORY $<TARGET_FILE_DIR:hdl_toy_tests>)
    set_tests_properties(hdl_toy_tests PROPERTIES
      TIMEOUT 180
      LABELS "gui;toy"
      RESOURCE_LOCK hdl_gui_desktop)
  endif()
endif()

install(TARGETS hdllib
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
install(DIRECTORY include/ DESTINATION include)
