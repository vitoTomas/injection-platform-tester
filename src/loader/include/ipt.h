#ifndef _IPT_H_
#define _IPT_H_

#define ARGS_MAX    32

enum Routine {
    INVAL = 0,
    REROUTE,
    PARAM,
    RET
};

#define REROUTE_ROUTINE    "reroute"
#define PARAM_ROUTINE      "param"
#define RETURN_ROUTINE     "return"
#define ROUTINE_MAX        20

#define CODE_OK                    0
#define CODE_PARAM_ROUTINE         1 /* Invalid routine. */
#define CODE_PARAM_PATH            2 /* Invalid parameter path. */
#define CODE_MISSING_INJECTABLE    3 /* Missing injectable path. */
#define CODE_MISSING_ARGS          4 /* No data for function arguments. */
#define CODE_ERR_OTHER             64

#define ARGS_DELIM                 ","

/*
 * Program context defines which BPF defined
 * routine needs to be run with the data provided.
 */
struct Context {
    enum Routine rte;
    char tracee_path[PATH_MAX];
    char injectable_path[PATH_MAX];
    char args[ARGS_MAX];
    char sym_name[NAME_MAX];
    int code;
};

#endif
