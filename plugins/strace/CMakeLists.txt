list(APPEND SABRE_PLUGIN_C_FLAGS "-Wall" "-Werror" "-Wno-erro=unused-parameter")

sabre_add_plugin(strace
  strace.c)
