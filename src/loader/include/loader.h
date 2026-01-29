#ifndef _LOADER_H_
#define _LOADER_H_

#include "ipt.h"

/*
 * Verify that the program context is valid.
 */
int context_checker(struct Context *ctx);

/*
 * Initialize the loader.
 *
 * Runs loader routines defined in the program context.
 */
int loader_initialize(struct Context *ctx);

#endif
