cmake_minimum_required(VERSION 4.2)
project(
        flowray
        VERSION 0.1.0
        DESCRIPTION "Linux application network activity analyzer"
        LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)

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
