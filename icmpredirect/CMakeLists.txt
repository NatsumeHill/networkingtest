cmake_minimum_required(VERSION 3.0.0)
project(icmp VERSION 0.0.1)

include(CTest)
enable_testing()
add_executable(icmp icmpredirect.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
