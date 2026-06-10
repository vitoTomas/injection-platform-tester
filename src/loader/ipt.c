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
    printf("Usage: %s --tracee|-t PROGRAM " \
                   "--routine|-r <reroute|param|return> " \
                   "--symbol|-s FUNC_NAME " \
                   "[--injectable|-i SO] " \
                   "[--offfset|-o HEXVAL] " \
                   "[--stripped|-p] " \
                   "[--args|-a ARGS] " \
                   "[--rc|-c RETURN_CODE] " \
                   "[--bootstrap|-b] " \
                   "[--debug|-d] " \
                   "[--quiet|-q] " \
                   "[--persist|-x]\n",
                   prog_name);
}
      
int main(int argc, char *argv[])
{
    int opt;
    int long_index = 0;
    int quiet = 0;
    int rc = CODE_OK;

    struct Context ctx;
    ctx.rte = INVAL;
    ctx.tracee_path[0] = '\0';
    ctx.args[0] = '\0';
    ctx.sym_name[0] = '\0';
    ctx.offset = 0;
    ctx.stripped = 0;
    ctx.bootstrap = 0;
    ctx.debug = 0;
    ctx.persist = 0;

    static struct option long_options[] = {
        {"tracee", required_argument, 0, 't'},
        {"routine", required_argument, 0, 'r'},
        {"injectable", optional_argument, 0, 'i'},
        {"args", optional_argument, 0, 'a'},
        {"offset", optional_argument, 0, 'o'},
        {"stripped", no_argument, 0, 'p'},
        {"rc", optional_argument, 0, 'c'},
        {"symbol", optional_argument, 0, 's'},
        {"bootstrap", no_argument, 0, 'b'},
        {"debug", no_argument, 0, 'd'},
        {"persist", no_argument, 0, 'x'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "t:r:i:o:a:c:s:pbdqxh",
                              long_options, &long_index)) != -1) {

        switch (opt) {
        case 't':
            if (strnlen(optarg, PATH_MAX) == PATH_MAX) {
                printf(PNAME" Tracee path too large.\n");
                rc = CODE_PARAM_PATH;
                goto end;
            }

            realpath(optarg, ctx.tracee_path);

            if (!quiet)
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
                printf(PNAME" No valid routine selected. " \
                       "(reroute, param, return)\n");

                rc = CODE_PARAM_ROUTINE;
                goto end;
            }

            if (!quiet)
                printf("**** ROUTINE: %s\n", optarg);

            break;
        case 'i':
            if (strnlen(optarg, PATH_MAX) == PATH_MAX) {
                printf(PNAME" Injectable path too large.\n");
                rc = CODE_PARAM_PATH;
                goto end;
            }

            realpath(optarg, ctx.injectable_path);

            if (!quiet)
                printf("**** INJECTABLE: %s\n", ctx.injectable_path);
            break;
        case 'o':
            if (strnlen(optarg, 18) == 18) {
                printf(PNAME" Offset too large.\n");
                rc = CODE_OFFSET;
                goto end;
            }

            ctx.offset = strtol(optarg, 0, 16);

            if (!quiet)
                printf("**** OFFSET: 0x%lx\n", ctx.offset);
            break;
        case 'p':
            ctx.stripped = 1;

            if (!quiet)
                printf("**** TRACEE STRIPPED\n");
            break;
        case 'a':
            if (strnlen(optarg, ARGS_MAX) == ARGS_MAX) {
                printf(PNAME" Argument size too large.\n");
                rc = CODE_PARAM_PATH;
                goto end;
            }
            strncpy(ctx.args, optarg, ARGS_MAX);

            if (!quiet)
                printf("**** ARGS: %s\n", ctx.args);
            break;
        case 'c':
            ctx.code = strtol(optarg, NULL, 10);
        case 's':
            if (strnlen(optarg, NAME_MAX) == NAME_MAX) {
                printf(PNAME" Symbol name too long.\n");
                rc = CODE_PARAM_PATH;
                goto end;
            }
            strncpy(ctx.sym_name, optarg, NAME_MAX);

            if (!quiet)
                printf("**** SYMBOL: %s\n", ctx.sym_name);
            break;
        case 'b':
            ctx.bootstrap = 1;

            if (!quiet)
                printf("**** BOOTSTRAP\n");
            break;
        case 'd':
            ctx.debug = 1;

            if (!quiet)
                printf("**** DEBUG\n");
            break;
        case 'q':
            quiet = 1;
            break;
        case 'x':
            ctx.bootstrap = 1;
            ctx.persist = 1;

            if (!quiet)
                printf("**** PERSIST\n");
            break;
        case 'h':
        default:
            _print_help(argv[0]);
            goto end;
        }
    }

    if (ctx.sym_name[0] == '\n' && ctx.offset == 0) {
        printf(PNAME" Invalid configuration, at least function name or offset "
               "must be provided. Aborting.\n");
        rc = CODE_ERR_OTHER;
        goto end;
    }

    rc = loader_initialize(&ctx);
    if (rc != CODE_OK) {
        _print_help(argv[0]);
        goto end;
    }
    
end:
    exit(rc);
}
