cmake_minimum_required(VERSION 3.15)
project(domaindb)

set(CMAKE_CXX_STANDARD 17)

add_executable(domaindb main.cpp domain_tree.cpp Tools/json11.cpp)