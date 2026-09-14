cmake_minimum_required(VERSION 4.2)
project(
        flowray
        VERSION 0.2.0
        DESCRIPTION "Linux application network activity analyzer"
        LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

FetchContent_Declare(
        CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.7.2
        GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(CLI11)

add_executable(flowray main.cpp
        src/pid.cpp
        src/socket.cpp
        headers/socket.h
        src/pid_child.cpp
        src/output.cpp
        headers/pid.h
        headers/output.h
        headers/data.h
        src/proc_name.cpp
        headers/proc_name.h
)

target_link_libraries(flowray PRIVATE CLI11::CLI11)

target_compile_options(flowray PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)