#ifndef X86_DECODER_H
#define X86_DECODER_H

#include <stdbool.h>

#include "compiler.h"

enum { REX_B = 0x01, REX_X = 0x02, REX_R = 0x04, REX_W = 0x08 };

unsigned short next_inst(const char **ip,
                         bool is64bit,
                         bool *has_prefix,
                         char **rex_ptr,
                         char **mod_rm_ptr,
                         char **sib_ptr,
                         bool *is_group) __internal;

#endif  // X86_DECODER_H
