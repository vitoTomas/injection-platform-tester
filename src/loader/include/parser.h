#ifndef _PARSER_H_
#define _PARSER_H_

#define MAPS     "/proc/%d/maps"
#define SIZE     (sizeof(MAPS) + 5)
#define LINE_SIZE    512
#define PATH_SIZE    256

unsigned long get_target_function_address(pid_t pid,
                                          const char *so_path,
                                          const char *func_name);

#endif
