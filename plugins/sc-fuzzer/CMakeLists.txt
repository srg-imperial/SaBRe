sabre_add_plugin(sc-fuzzer
  sc-fuzzer.c)

target_compile_options(sc-fuzzer PRIVATE -Wall -Wextra -Werror -Wno-error=unused-parameter)
