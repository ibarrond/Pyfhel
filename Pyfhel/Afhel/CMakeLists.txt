# This can be used to build locally Afhel and test demos.  
cmake_minimum_required (VERSION 3.9...3.17)

project(Afhel)

find_package(SEAL 3.7 REQUIRED)

add_library(afseal Afseal.cpp)
target_link_libraries(afseal SEAL::seal)

add_executable(demo_afseal_batch Demos/Demo_Afseal_batch.cpp)
target_link_libraries(demo_afseal_batch afseal)
