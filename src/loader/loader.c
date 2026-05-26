#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <bpf/libbpf.h>

/*
 * BPF routine to send SIGSTOP upon
 * reaching the tracepoint.
 */
#include <bpf_signal.h>

#include "include/ipt.h"
#include "include/parser.h"

#define PRELOAD  "LD_PRELOAD=%s"
#define PID_ANY  -1

static int _libbpf_print_fn(enum libbpf_print_level level, const char *format,
                            va_list args)
{
        (void) level;

        return vfprintf(stderr, format, args);
}

static int _load_bpf_routine(enum Routine rte, const char *tracee_path,
                             const char *sym_name, unsigned long offset,
                             void *skel)
{
  /*
   * In this function, routine is referenced as a 'BPF program',
   * which is what a BPF routine in essence is. Name 'routine' is
   * a more abstract term in this context, with the plan of it being
   * customizable by the IPT test writer on an abstracted level.
   */
  struct bpf_uprobe_opts uopts;
  struct bpf_link *link;
  int rc;

  (void) rte;

  memset(&uopts, 0, sizeof(struct bpf_uprobe_opts));
  uopts.sz = sizeof(struct bpf_uprobe_opts);
  uopts.bpf_cookie = 99;
  uopts.retprobe = false;
  uopts.func_name = sym_name;

  /*
   * libbpf erros and debug info callback function.
   */
  libbpf_set_print(_libbpf_print_fn);

  /*
   * Load BPF program into loader process memory.
   */
  skel = bpf_signal__open();
  if (!skel) {
    perror("bpf open");
    printf("Internal error.\n");
    return CODE_ERR_OTHER;    
  }

  /*
   * Set BPF program data.
   */

  /*
   * Load and verify BPF program in the kernel.
   */
  rc = bpf_signal__load(skel);
  if (rc) {
    perror("bpf load");
    printf("Internal error.\n");
    return rc;
  }

  /*
   * Attach the probe to a perf event.
   */
  link = bpf_program__attach_uprobe_opts(((struct bpf_signal *)skel)->progs.handler, PID_ANY,
                                         tracee_path, offset, &uopts);
  if (!link) {
    perror("bpf_attach_uprobe");
    printf("Internal error.\n");
    return CODE_ERR_OTHER;
  }
  
  
  return CODE_OK;
}

static inline void _unload_bpf_routine(struct bpf_signal *skel)
{
  bpf_signal__destroy(skel);
}

static int _reroute_routine(const char *tracee_path, const char *inj_path,
                            const char *sym_name)
{
  struct bpf_signal *skel = NULL;
  struct user_regs_struct regs;
  pid_t pid;
  char preload_expression[PATH_MAX + sizeof(PRELOAD)];
  unsigned long sym_offset = 0; /* Offset from the function symbol. */
  unsigned long target_address;
  int status;
  int rc;

  char *args[] = { NULL };
  char *envs[2] = { NULL, NULL };

  pid = fork();
  switch (pid) {
    case -1:
      printf("Internal error.\n");
      perror("fork");
      return CODE_ERR_OTHER;
    case 0:
      snprintf(preload_expression,
               PATH_MAX + sizeof(PRELOAD),
               PRELOAD, inj_path);
      envs[0] = preload_expression;

      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execve(tracee_path, args, envs);
      break;
    default:
      printf("Loader started the tracee process with pid: %d\n", pid);
  }

  ptrace(PTRACE_CONT, pid, NULL, 0);
  waitpid(pid, &status, WUNTRACED);

  ptrace(PTRACE_CONT, pid, NULL, 0);
  waitpid(pid, &status, WUNTRACED);

  target_address = get_target_function_address(pid, inj_path, sym_name);
  printf("Target function address: 0x%lx\n", target_address);

  rc = _load_bpf_routine(REROUTE, tracee_path, sym_name, sym_offset, skel);
  if (rc != CODE_OK)
    return rc;

  printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing"
         "/trace_pipe` to see output of the BPF programs.\n");
  printf("Press Ctrl+C to terminate.\n");

  ptrace(PTRACE_CONT, pid, NULL, 0);
  waitpid(pid, &status, WUNTRACED);

  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  printf("Instruction pointer at probe time: 0x%llx\n", regs.rip);
  regs.rip = target_address;
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);

  ptrace(PTRACE_CONT, pid, NULL, 0);
  printf("Set IP (instruction pointer) and continued tracee execution...\n");

  while (true)
    sleep(1);

  _unload_bpf_routine(skel);

  return CODE_OK;
}

static int _param_routine(const char *tracee_path, const char *sym_name,
                          const char params[5][10])
{
  struct bpf_signal *skel = NULL;
  struct user_regs_struct regs;
  unsigned long sym_offset = 0;
  unsigned index;
  long long value;
  pid_t pid;
  int status;
  int rc;
  
  rc = _load_bpf_routine(REROUTE, tracee_path, sym_name, sym_offset, skel);

  /*
   * The idea is to (later) automatically detect which process stopped
   * so it can be traced properly.
   */
  printf("Input process ID: \n");
  scanf("%d", &pid);

  printf("Attaching to process with pid: %d....\n", pid);
  ptrace(PTRACE_ATTACH, pid, NULL, NULL);

  waitpid(pid, &status, 0);

  ptrace(PTRACE_GETREGS, pid, NULL, &regs);

  /*
   * NOTE: currently compatible only with x86_64,
   * only 5 parameters supported and parameters are
   * expected to be integers.
   */

  for (index = 0; index < 5; index++) {
    if (!params[index])
      break;
    errno = 0;
    value = strtol(params[index], NULL, 10);
    if (errno)
      continue;

    printf("Setting param %d to %lld\n", index + 1, value);

    switch (index) {
      case 0:
        regs.rdi = value;
        break;
      case 1:
        regs.rsi = value;
        break;
      case 2:
        regs.rdx = value;
        break;
      case 3:
        regs.rcx = value;
        break;
      case 4:
        regs.r8 = value;
    }
  }

  ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  ptrace(PTRACE_DETACH, pid, NULL, NULL);

  /*
   * Continue tracee execution.
   */
  kill(pid, SIGCONT);

  return rc;
}

static int _context_checker(struct Context *ctx)
{
  if (!ctx) {
    printf("Internal error (NULL pointer).\n");
    return CODE_ERR_OTHER;
  }

  switch (ctx->rte) {
    case REROUTE:
      if (strlen(ctx->injectable_path) == 0) {
        printf("Missing injectable path for reroute routine.\n");
        return CODE_MISSING_INJECTABLE;
      }
      break;
    case PARAM:
        if (strlen(ctx->args) == 0) {
          printf("Missing data for function arguments in param routine.\n");
          return CODE_MISSING_ARGS;
        }
        break;
    case RET:
        break;
    default:
      printf("Invalid routine or another error occurred.\n");
      return CODE_ERR_OTHER;
  }

  return CODE_OK;
}

static void _split_args(char params[5][10], const char *args)
{
  unsigned index = 0;
  char copy[ARGS_MAX];
  char *token;

  strncpy(copy, args, ARGS_MAX);

  token = strtok(copy, ARGS_DELIM);
  while (token) {
    strncpy(params[index], token, 10);
    token = strtok(NULL, ARGS_DELIM);
    index++;
  }
}

int loader_initialize(struct Context *ctx)
{
  char params[5][10] = {{ '\0' }};
  int rc = CODE_OK;

  rc = _context_checker(ctx);
  if (rc)
    goto end;

  switch (ctx->rte) {
    case REROUTE:
      rc = _reroute_routine(ctx->tracee_path, ctx->injectable_path,
                            ctx->sym_name);
      break;
    case PARAM:
      _split_args(params, ctx->args);
      rc = _param_routine(ctx->tracee_path, ctx->sym_name, params);

      break;
    case RET:
    default:
      /* Should not happen since it is checked by _context_checker. */
      /* TODO: Implement other routines. */
      printf("Routine not supported yet.\n");
  }

end:
  return rc;
}
