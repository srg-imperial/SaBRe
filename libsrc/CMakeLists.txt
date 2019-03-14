if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")

include_directories(${CMAKE_SOURCE_DIR}/includes)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra -Werror -fPIC")

add_library(libsrc STATIC malloc/malloc.c malloc/mlock.c)

endif ()