cmake_minimum_required(VERSION 3.15)
project(domaindb)

#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)

add_executable(${PROJECT_NAME} main.cpp domain_tree.cpp Tools/json11.cpp Tools/base64.cpp external_classifier.cpp external_classifier.h)
target_link_libraries(${PROJECT_NAME} curl -latomic pthread )
