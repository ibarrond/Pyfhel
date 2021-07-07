cmake_minimum_required (VERSION 3.9...3.17)

project(Afhel)

find_package(SEAL 3.6 CONFIG REQUIRED)


add_library(afseal Afhel.h Afseal.cpp)
target_link_libraries(afseal SEAL::seal)

add_executable(demo_afhel Demos/Demo_Afhel.cpp)
target_link_libraries(demo_afhel afhel)

add_executable(demo_afseal_batch Demos/Demo_Afseal_batch.cpp)
target_link_libraries(demo_afseal_batch afhel)

add_executable(demo_afseal_int Demos/Demo_Afseal_int.cpp)
target_link_libraries(demo_afseal_int afhel)

add_executable(demo_afseal_io Demos/Demo_Afseal_IO.cpp)
target_link_libraries(demo_afseal_io afhel)