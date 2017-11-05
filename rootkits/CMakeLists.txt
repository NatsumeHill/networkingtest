cmake_minimum_required(VERSION 3.0.0)
project(backdoor VERSION 0.0.0)

include(CTest)
enable_testing()

add_executable(backdoor ./src/backdoor.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
