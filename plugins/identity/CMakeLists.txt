include_directories(${CMAKE_SOURCE_DIR}/includes/plugins)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra -Werror -Wno-error=unused-parameter")

add_library(identity SHARED identity.c)
target_link_libraries(identity ${CMAKE_SYSTEM_PROCESSOR})
