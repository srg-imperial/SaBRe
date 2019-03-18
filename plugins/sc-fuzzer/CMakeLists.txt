include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/plugins)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra -Werror -Wno-error=unused-parameter")

add_library(sc-fuzzer SHARED sc-fuzzer.c)
target_link_libraries(sc-fuzzer ${CMAKE_SYSTEM_PROCESSOR})


