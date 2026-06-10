#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <bpf/libbpf.h>

/*
 * BPF routine to send SIGSTOP upon
 * reaching the tracepoint.
 */
#include <bpf_signal.h>
#include <bpf_execve.h>

#include "include/ipt.h"
#include "include/parser.h"

#define PRELOAD  "LD_PRELOAD=%s"
#define PID_ANY  -1

static char tty_name_stolen[5];
int debug;

static int _libbpf_print_fn(enum libbpf_print_level level, const char *format,
                            va_list args)
{
  (void) level;

  return vfprintf(stderr, format, args);
}

struct event {
  __u32 pstart;
  __u32 pid;
  char tty_name[64];
  char comm[16];
};

static int __handle_exec_event_ringbuff(void *ctx, void *data, size_t size)
{
  struct event *e = data;

  if (debug)
    printf(PNAME" pstart=%d, pid=%d, comm=%s, tty=%s\n",
      e->pstart, e->pid, e->comm, e->tty_name);
  if (e->pstart) {
    strncpy(tty_name_stolen, e->tty_name, sizeof(tty_name_stolen));
    return 1;
  }

  return 0;
}

static int _load_bpf_routine_alt(const char *tracee_path, const char *sym_name,
                                 unsigned long offset, int rb_exec_ev)
{
  struct bpf_kprobe_opts kopts;
  struct bpf_link *link;
  struct ring_buffer *ringbuff;
  void *skel;
  int rc;

  memset(&kopts, 0, sizeof(struct bpf_kprobe_opts));
  kopts.sz = sizeof(struct bpf_kprobe_opts);
  kopts.bpf_cookie = 89;
  kopts.retprobe = false;

  skel = bpf_execve__open();
  if (!skel) {
    perror(PNAME" bpf open");
    printf(PNAME" Internal error.\n");
    return CODE_ERR_OTHER;
  }

  if (rb_exec_ev)
    strncpy(((struct bpf_execve *)skel)->rodata->tracee_path, tracee_path, 256);

  rc = bpf_signal__load(skel);
  if (rc) {
    perror(PNAME" bpf load");
    printf(PNAME" Internal error.\n");
    return rc;
  }

  link = bpf_program__attach_kprobe_opts(((struct bpf_execve *)skel)->progs.handler,
                                         sym_name,
                                         &kopts);
  if (!link) {
    /* Attempt to auto-attach */
    link = bpf_program__attach(skel);
    if (!link) {
      perror(PNAME" bpf_attach_kprobe");
      printf(PNAME" Internal error.\n");
      return CODE_ERR_OTHER;
    }
  }

  if (rb_exec_ev) {
    ringbuff = ring_buffer__new(
      bpf_map__fd(((struct bpf_execve *)skel)->maps.ringbuff),
      __handle_exec_event_ringbuff,
      NULL,
      NULL
    );

    while (!ring_buffer__poll(ringbuff, 100));

    ring_buffer__free(ringbuff);
    bpf_link__destroy(link);
    bpf_execve__destroy(skel);
  }

  return CODE_OK;
}

static int _load_bpf_routine(enum Routine rte, const char *tracee_path,
                             const char *sym_name, unsigned long offset,
                             void *skel, int stripped, int rb_exec_ev)
{
  /*
   * In this function, routine is referenced as a 'BPF program',
   * which is what a BPF routine in essence is. Name 'routine' is
   * a more abstract term in this context, with the plan of it being
   * customizable by the IPT test writer on an abstracted level.
   */

  if (rte == ALTERNATE)
    return _load_bpf_routine_alt(tracee_path, sym_name, offset, rb_exec_ev);

  struct bpf_uprobe_opts uopts;
  struct bpf_link *link;
  int rc;

  memset(&uopts, 0, sizeof(struct bpf_uprobe_opts));
  uopts.sz = sizeof(struct bpf_uprobe_opts);
  uopts.bpf_cookie = 99;
  uopts.retprobe = false;

  /*
   * If our tracee is stripped of symbols, there will be nothing
   * to find in the symbol table. Hence only the offset will be used.
   */
  if (!stripped)
    uopts.func_name = sym_name;
  else
    uopts.func_name = NULL;

  /*
   * Load BPF program into loader process memory.
   */
  skel = bpf_signal__open();
  if (!skel) {
    perror(PNAME" bpf open");
    printf(PNAME" Internal error.\n");
    return CODE_ERR_OTHER;    
  }

  /*
   * Set BPF program data.
   *
   * Load and verify BPF program in the kernel.
   */
  rc = bpf_signal__load(skel);
  if (rc) {
    perror(PNAME" bpf load");
    printf(PNAME" Internal error.\n");
    return rc;
  }

  /*
   * Attach the probe to a perf event.
   */
   link = bpf_program__attach_uprobe_opts(((struct bpf_signal *)skel)->progs.handler,
                                          PID_ANY,
                                          tracee_path, offset, &uopts);

  if (!link) {
    perror(PNAME" bpf_attach_uprobe");
    printf(PNAME" Internal error.\n");
    return CODE_ERR_OTHER;
  }
  
  return CODE_OK;
}

static inline void _unload_bpf_routine(struct bpf_signal *skel)
{
  bpf_signal__destroy(skel);
}

static int _bootstrap(const char *tracee_path,
                      const char *sym_name,
                      unsigned long offset)
{
  return _load_bpf_routine(ALTERNATE,
                           tracee_path, sym_name, offset, NULL, 0, 1);
}

static int _reroute_routine(const char *tracee_path, const char *inj_path,
                            const char *sym_name, unsigned long offset,
                            int stripped, int bootstrap)
{
  struct bpf_signal *skel = NULL;
  struct user_regs_struct regs;
  pid_t pid;
  char preload_expression[PATH_MAX + sizeof(PRELOAD)];
  char tty_path_stolen[64];
  unsigned long sym_offset = offset; /* Offset from the function symbol. */
  unsigned long target_address;
  int tty_fd_stolen;
  int status;
  int rc;

  char *args[] = { NULL };
  char *envs[2] = { NULL, NULL };

  pid = fork();
  switch (pid) {
    case -1:
      printf(PNAME" Internal error.\n");
      perror(PNAME" fork");
      return CODE_ERR_OTHER;
    case 0:
      snprintf(preload_expression,
               PATH_MAX + sizeof(PRELOAD),
               PRELOAD, inj_path);
      envs[0] = preload_expression;

      if (bootstrap) {
        if (strncmp(tty_name_stolen, "pts", 3) == 0 && isdigit(tty_name_stolen[3]))
          snprintf(tty_path_stolen, sizeof(tty_path_stolen), "/dev/pts/%s", tty_name_stolen + 3);
        else
          snprintf(tty_path_stolen, sizeof(tty_path_stolen), "/dev/%s", tty_name_stolen);

        tty_fd_stolen = open(tty_path_stolen, O_RDWR);
        if (tty_fd_stolen < 0) {
          perror("open");
          exit(1);
        }

        dup2(tty_fd_stolen, STDIN_FILENO);
        dup2(tty_fd_stolen, STDOUT_FILENO);
        dup2(tty_fd_stolen, STDERR_FILENO);
        close(tty_fd_stolen);
      }

      setsid();

      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execve(tracee_path, args, envs);
      break;
    default:
      if (debug)
        printf(PNAME" Loader started the tracee process with pid: %d\n", pid);
  }

  ptrace(PTRACE_CONT, pid, NULL, 0);
  waitpid(pid, &status, WUNTRACED);

  ptrace(PTRACE_CONT, pid, NULL, 0);
  waitpid(pid, &status, WUNTRACED);

  target_address = get_target_function_address(pid, inj_path, sym_name);
  if (debug)
    printf(PNAME" Target function address: 0x%lx\n", target_address);

  rc = _load_bpf_routine(REROUTE, tracee_path, sym_name, sym_offset, skel,
                         stripped, 0);
  if (rc != CODE_OK)
    return rc;

  if (debug) {
    printf(PNAME" Successfully started! Please run `sudo cat /sys/kernel/"
      "debug/tracing/trace_pipe` to see output of the BPF programs.\n");
    printf(PNAME" Press Ctrl+C to terminate.\n");
  }

  while (true) {
    ptrace(PTRACE_CONT, pid, NULL, 0);
    rc = waitpid(pid, &status, WUNTRACED);
    if (rc == -1)
      break;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (debug)
      printf(PNAME" Instruction pointer at probe time: 0x%llx\n", regs.rip);
    regs.rip = target_address;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    if (debug)
      printf(PNAME" Set IP (instruction pointer) and continued tracee execution...\n");
  }

  _unload_bpf_routine(skel);

  return CODE_OK;
}

static int _param_routine(const char *tracee_path, const char *sym_name,
                          const char params[5][10], int stripped)
{
  struct bpf_signal *skel = NULL;
  struct user_regs_struct regs;
  unsigned long sym_offset = 0;
  unsigned index;
  long long value;
  pid_t pid;
  int status;
  int rc;
  
  rc = _load_bpf_routine(REROUTE, tracee_path, sym_name, sym_offset, skel,
                         stripped, 0);

  /*
   * The idea is to (later) automatically detect which process stopped
   * so it can be traced properly.
   */
  printf(PNAME" Input process ID: \n");
  scanf("%d", &pid);

  if (debug)
    printf(PNAME" Attaching to process with pid: %d....\n", pid);
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

    if (debug)
      printf(PNAME" Setting param %d to %lld\n", index + 1, value);

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
    printf(PNAME" Internal error (NULL pointer).\n");
    return CODE_ERR_OTHER;
  }

  switch (ctx->rte) {
    case REROUTE:
      if (strlen(ctx->injectable_path) == 0) {
        printf(PNAME" Missing injectable path for reroute routine.\n");
        return CODE_MISSING_INJECTABLE;
      }
      break;
    case PARAM:
        if (strlen(ctx->args) == 0) {
          printf(PNAME" Missing data for function arguments in param routine.\n");
          return CODE_MISSING_ARGS;
        }
        break;
    case RET:
        break;
    default:
      printf(PNAME" Invalid routine or another error occurred.\n");
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

  debug = ctx->debug;

  rc = _context_checker(ctx);
  if (rc)
    goto end;

  if (ctx->debug)
    libbpf_set_print(_libbpf_print_fn);
  else
    libbpf_set_print(NULL);

  switch (ctx->rte) {
    case REROUTE:
      do {
        if (ctx->bootstrap) {
          rc = _bootstrap(ctx->tracee_path, "__x64_sys_execve", ctx->offset);
          if (rc != CODE_OK)
            break;
        }

        rc = _reroute_routine(ctx->tracee_path, ctx->injectable_path,
                              ctx->sym_name, ctx->offset, ctx->stripped,
                              ctx->bootstrap);
      } while(ctx->persist);

      break;
    case PARAM:
      _split_args(params, ctx->args);
      rc = _param_routine(ctx->tracee_path, ctx->sym_name, params,
                          ctx->stripped);

      break;
    case RET:
    default:
      /* Should not happen since it is checked by _context_checker. */
      /* TODO: Implement other routines. */
      printf(PNAME" Invalid routine parameter.\n");
  }

end:
  return rc;
}
