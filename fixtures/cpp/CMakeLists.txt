cmake_minimum_required(VERSION 3.16)
project(aflpp_mcp_fixture_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(aflpp_mcp_fixture src/main.cpp)
target_compile_options(aflpp_mcp_fixture PRIVATE -O2 -g)

