cmake_minimum_required(VERSION 4.2)
project(
        flowray
        VERSION 0.1.0
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
        pid.cpp
        main.h
        socket.cpp
        socket.h
        pid_child.cpp
        output.cpp
        pid.h
        output.h
        data.h
)

target_link_libraries(flowray PRIVATE CLI11::CLI11)

target_compile_options(flowray PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)