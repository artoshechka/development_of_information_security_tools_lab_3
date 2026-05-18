cmake_minimum_required(VERSION 3.10)
project(DLLInjection CXX)

set(CMAKE_CXX_STANDARD 17)

add_library(VirusDLL SHARED VirusDLL/Source.cpp)
target_link_libraries(VirusDLL PRIVATE psapi)

add_executable(TargetProcess TargetProcess/Source.cpp) 

add_executable(DLLLoader DLLLoader/Source.cpp)

add_executable(DLLInjectorAsProcess DLLInjectorAsProcess/Source.cpp)

add_library(DllInjectorAsDll SHARED DllInjectorAsDll/Source.cpp DllInjectorAsDll/DllInjectorAsDll.def)
