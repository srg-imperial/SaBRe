sabre_add_plugin(identity
  identity.c)

target_compile_options(identity PRIVATE -Wall -Wextra -Werror -Wno-error=unused-parameter)
