cmake_minimum_required(VERSION 3.20)
project(mwdec LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(mwdec_core STATIC
    src/pe.cpp
    src/profile.cpp
    src/autoboot.cpp
    src/bootstrap.cpp
    src/imports.cpp
    src/plan.cpp
    src/strings.cpp
    src/verify.cpp
    src/writers.cpp
    src/writerkey.cpp
)
target_include_directories(mwdec_core PUBLIC src)
if(MSVC)
    target_compile_options(mwdec_core PUBLIC /W4 /permissive- /utf-8)
    target_compile_definitions(mwdec_core PUBLIC _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(mwdec_core PUBLIC -Wall -Wextra)
endif()

# `mwdec flow` (src/flow): the same capstone and unicorn builds the Python
# tools use. Headers from the Python packages; the DLLs are bound at run time
# (GetProcAddress) and copied next to mwdec.exe, so the other commands run
# without them.
foreach(_pkg capstone unicorn)
    string(TOUPPER ${_pkg} _PKG)
    if(NOT ${_PKG}_DIR)
        execute_process(COMMAND py -3 -c "import ${_pkg},os;print(os.path.dirname(${_pkg}.__file__))"
                        OUTPUT_VARIABLE _dir OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE _rc)
        if(NOT _rc EQUAL 0)
            message(FATAL_ERROR "set ${_PKG}_DIR to the ${_pkg} Python package directory")
        endif()
        file(TO_CMAKE_PATH "${_dir}" _dir)
        set(${_PKG}_DIR "${_dir}" CACHE PATH "${_pkg} Python package directory (include/ and lib/)")
    endif()
endforeach()

add_library(mwdec_flow STATIC
    src/flow/dyn.cpp
    src/flow/dec.cpp
    src/flow/pyutil.cpp
    src/flow/json.cpp
    src/flow/image.cpp
    src/flow/code.cpp
    src/flow/idiom.cpp
    src/flow/liveness.cpp
    src/flow/walker.cpp
    src/flow/planner.cpp
    src/flow/checks.cpp
    src/flow/sweep.cpp
    src/flow/pipeline.cpp
    src/flow/report.cpp
    src/flow/flow_cmd.cpp
    src/flow/writers_find.cpp
    src/flow/tables.cpp
    src/flow/boot.cpp
    src/flow/junk.cpp
)
target_include_directories(mwdec_flow PUBLIC src)
target_include_directories(mwdec_flow SYSTEM PUBLIC "${CAPSTONE_DIR}/include" "${UNICORN_DIR}/include")
if(MSVC)
    target_compile_options(mwdec_flow PRIVATE /W4 /permissive- /utf-8 /external:W0)
    target_compile_definitions(mwdec_flow PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
target_link_libraries(mwdec_flow PUBLIC psapi)

add_executable(mwdec src/main.cpp)
target_link_libraries(mwdec PRIVATE mwdec_core mwdec_flow)
add_custom_command(TARGET mwdec POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CAPSTONE_DIR}/lib/capstone.dll" $<TARGET_FILE_DIR:mwdec>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${UNICORN_DIR}/lib/unicorn.dll" $<TARGET_FILE_DIR:mwdec>)

enable_testing()
add_executable(mwdec_selftest tests/selftest.cpp)
target_link_libraries(mwdec_selftest PRIVATE mwdec_core)
add_test(NAME selftest COMMAND mwdec_selftest)
