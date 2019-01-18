#ifndef GLOBAL_VARS_H
#define GLOBAL_VARS_H

#include "vx_api_defs.h"

#define MAX_ICEPT_RECORDS 50
#define MAX_ICEPT_STRLEN 80

typedef struct {
    char lib_name[MAX_ICEPT_STRLEN];
    char fn_name[MAX_ICEPT_STRLEN];
    vx_icept_callback_fn callback;
} vx_fn_icept_local_struct;

extern int registered_icept_cnt;
extern vx_fn_icept_local_struct intercept_records[MAX_ICEPT_RECORDS];
extern vx_icept_vdso_callback_fn vdso_callback;
extern vx_sc_handler_fn sc_handler;
extern const char *known_syscall_libs[];

#endif /* !GLOBAL_VARS_H */
