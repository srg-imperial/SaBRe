sabre_add_plugin(strace
  strace.c)

target_compile_options(strace PRIVATE -Wall -Wextra -Werror -Wno-error=unused-parameter)
