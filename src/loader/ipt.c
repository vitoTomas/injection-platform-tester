#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include "include/ipt.h"
#include "include/loader.h"

static void _print_help(const char *prog_name)
{
    if (prog_name == NULL)
        return;
    printf("Usage: %s [--tracee|-t PROGRAM] " \
                   "[--routine|-r ROUTINE=<reroute|param|return> " \
                   "[<reroute> --injectable|-i SO] [<param> --args|-a ARGS] " \
                   "[<return> --rc|-c RETURN_CODE]] [--symbol|-s FUNC_NAME]\n",
                   prog_name);
}
      
int main(int argc, char *argv[])
{
    int opt;
    int long_index = 0;
    int rc = CODE_OK;

    struct Context ctx;
    ctx.rte = INVAL;
    ctx.tracee_path[0] = '\0';
    ctx.args[0] = '\0';
    ctx.sym_name[0] = '\0';

    static struct option long_options[] = {
        {"tracee", required_argument, 0, 't'},
        {"routine", required_argument, 0, 'r'},
        {"injectable", optional_argument, 0, 'i'},
        {"args", optional_argument, 0, 'a'},
        {"rc", optional_argument, 0, 'c'},
        {"symbol", required_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "t:r:i:a:c:s:h",
                              long_options, &long_index)) != -1) {

        switch (opt) {
        case 't':
            if (strnlen(optarg, PATH_MAX) == PATH_MAX) {
                printf("Tracee path too large.\n");
                rc = CODE_PARAM_PATH;
                goto end;
            }

            realpath(optarg, ctx.tracee_path);
            printf("**** TRACEE: %s\n", ctx.tracee_path);
            break;
        case 'r':
            /*
             * Extrapolate selected routine.
             */
            if (!strncmp(REROUTE_ROUTINE, optarg, ROUTINE_MAX))
                ctx.rte = REROUTE;

            if (!strncmp(PARAM_ROUTINE, optarg, ROUTINE_MAX))
                ctx.rte = PARAM;
            
            if (!strncmp(RETURN_ROUTINE, optarg, ROUTINE_MAX))
                ctx.rte = RET;

            if (ctx.rte == INVAL) {
                printf("No valid routine selected. " \
                       "(reroute, param, return)\n");

                rc = CODE_PARAM_ROUTINE;
                goto end;
            }

            printf("**** ROUTINE: %s\n", optarg);

            break;
        case 'i':
            if (strnlen(optarg, PATH_MAX) == PATH_MAX) {
                printf("Injectable path too large.\n");
                rc = CODE_PARAM_PATH;
                goto end;
            }

            realpath(optarg, ctx.injectable_path);
            printf("**** INJECTABLE: %s\n", ctx.injectable_path);
            break;
        case 'a':
            if (strnlen(optarg, ARGS_MAX) == ARGS_MAX) {
                printf("Argument size too large.\n");
                rc = CODE_PARAM_PATH;
                goto end;
            }
            strncpy(ctx.args, optarg, ARGS_MAX);
            printf("**** ARGS: %s\n", ctx.args);
            break;
        case 'c':
            ctx.code = strtol(optarg, NULL, 10);
        case 's':
            if (strnlen(optarg, NAME_MAX) == NAME_MAX) {
                printf("Symbol name too long.\n");
                rc = CODE_PARAM_PATH;
                goto end;
            }
            strncpy(ctx.sym_name, optarg, NAME_MAX);
            printf("**** SYMBOL: %s\n", ctx.sym_name);
            break;
        case 'h':
        default:
            _print_help(argv[0]);
            goto end;
        }
    }

    rc = loader_initialize(&ctx);
    if (rc != CODE_OK) {
        _print_help(argv[0]);
        goto end;
    }
    
end:
    exit(rc);
}
