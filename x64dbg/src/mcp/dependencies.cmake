include_guard(GLOBAL)
include(FetchContent)

if(NOT MSVC OR CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.44.35228.0")
    message(FATAL_ERROR "Native MCP requires MSVC 19.44.35228.0 or later; other toolchains are unverified")
endif()

if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

function(mcp_source_archive name url digest)
    FetchContent_Declare(${name} URL "${url}" URL_HASH "SHA256=${digest}")
    FetchContent_GetProperties(${name})
    if(NOT ${name}_POPULATED)
        FetchContent_Populate(${name})
    endif()
    set(${name}_SOURCE_DIR "${${name}_SOURCE_DIR}" PARENT_SCOPE)
endfunction()

mcp_source_archive(mcp_boost
    "https://archives.boost.io/release/1.92.0/source/boost_1_92_0.tar.gz"
    "c4a3b310ddd2472416e091067166b0713be97c63f38c212c484ada022fd296ce")
mcp_source_archive(mcp_json_source
    "https://codeload.github.com/nlohmann/json/tar.gz/refs/tags/v3.12.0"
    "4b92eb0c06d10683f7447ce9406cb97cd4b453be18d7279320f7b2f025c10187")
mcp_source_archive(mcp_sqlite_source
    "https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip"
    "1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d")
mcp_source_archive(mcp_quickjs_source
    "https://codeload.github.com/quickjs-ng/quickjs/tar.gz/refs/tags/v0.17.0"
    "559bc4c420475e55c7ab4510adbc562f55d7524d75e8e89d79ce4bb02f5687d9")

add_library(mcp_json INTERFACE)
target_include_directories(mcp_json SYSTEM INTERFACE "${mcp_json_source_SOURCE_DIR}/single_include")

add_library(mcp_http INTERFACE)
target_include_directories(mcp_http SYSTEM INTERFACE "${mcp_boost_SOURCE_DIR}")
target_compile_definitions(mcp_http INTERFACE BOOST_ALL_NO_LIB WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_link_libraries(mcp_http INTERFACE ws2_32 mswsock)

add_library(mcp_sqlite STATIC "${mcp_sqlite_source_SOURCE_DIR}/sqlite3.c")
target_include_directories(mcp_sqlite SYSTEM PUBLIC "${mcp_sqlite_source_SOURCE_DIR}")
target_compile_definitions(mcp_sqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_DQS=0 SQLITE_DEFAULT_FOREIGN_KEYS=1 SQLITE_OMIT_LOAD_EXTENSION)
set_target_properties(mcp_sqlite PROPERTIES UNITY_BUILD OFF)

add_library(mcp_quickjs STATIC
    "${mcp_quickjs_source_SOURCE_DIR}/dtoa.c"
    "${mcp_quickjs_source_SOURCE_DIR}/libregexp.c"
    "${mcp_quickjs_source_SOURCE_DIR}/libunicode.c"
    "${mcp_quickjs_source_SOURCE_DIR}/quickjs.c")
target_include_directories(mcp_quickjs SYSTEM PUBLIC "${mcp_quickjs_source_SOURCE_DIR}")
target_compile_definitions(mcp_quickjs PRIVATE QUICKJS_NG_BUILD _GNU_SOURCE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
target_compile_features(mcp_quickjs PRIVATE c_std_11)
set_target_properties(mcp_quickjs PROPERTIES UNITY_BUILD OFF)
if(MSVC)
    target_compile_options(mcp_quickjs PRIVATE /experimental:c11atomics)
endif()

set(mcp_notice_directory "${CMAKE_BINARY_DIR}/mcp-notices")
file(MAKE_DIRECTORY "${mcp_notice_directory}")
configure_file("${mcp_boost_SOURCE_DIR}/LICENSE_1_0.txt" "${mcp_notice_directory}/boost.txt" COPYONLY)
configure_file("${mcp_json_source_SOURCE_DIR}/LICENSE.MIT" "${mcp_notice_directory}/json.txt" COPYONLY)
configure_file("${mcp_quickjs_source_SOURCE_DIR}/LICENSE" "${mcp_notice_directory}/quickjs.txt" COPYONLY)
configure_file("${CMAKE_CURRENT_LIST_DIR}/notices/sqlite.txt" "${mcp_notice_directory}/sqlite.txt" COPYONLY)

file(GLOB_RECURSE mcp_contract_inputs CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_LIST_DIR}/common/*"
    "${CMAKE_CURRENT_LIST_DIR}/broker/*"
    "${CMAKE_CURRENT_LIST_DIR}/connect/*"
    "${PROJECT_SOURCE_DIR}/src/dbg/mcp/*")
list(APPEND mcp_contract_inputs "${CMAKE_CURRENT_LIST_FILE}" "${CMAKE_CURRENT_LIST_DIR}/dependencies.json" "${PROJECT_SOURCE_DIR}/cmake.toml")
list(SORT mcp_contract_inputs)
set(mcp_build_input "${CMAKE_CXX_COMPILER_ID};${CMAKE_CXX_COMPILER_VERSION};${CMAKE_SIZEOF_VOID_P};${CMAKE_BUILD_TYPE};${CMAKE_MSVC_RUNTIME_LIBRARY};${CMAKE_CXX_FLAGS};${CMAKE_CXX_FLAGS_RELEASE}")
foreach(mcp_input IN LISTS mcp_contract_inputs)
    file(SHA256 "${mcp_input}" mcp_input_hash)
    string(APPEND mcp_build_input ";${mcp_input_hash}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${mcp_input}")
endforeach()
string(SHA256 MCP_BUILD_ID "${mcp_build_input}")
configure_file("${CMAKE_CURRENT_LIST_DIR}/common/build_identity.h.in" "${CMAKE_BINARY_DIR}/mcp-generated/build_identity.h" @ONLY)
target_include_directories(mcp_json INTERFACE "${CMAKE_BINARY_DIR}/mcp-generated")
