cmake_minimum_required (VERSION 2.8)
project (SaBRe C ASM)

find_program(GCC_PATH gcc)

# Sources
add_subdirectory("libsrc")
add_subdirectory("loader")
file(GLOB subdirs CONFIGURE_DEPENDS "plugins/*")
foreach(subdir ${subdirs})
  add_subdirectory(${subdir})
endforeach()
