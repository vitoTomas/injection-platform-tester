#define __TARGET_ARCH_x86
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PNAME				"EXECVE DETECT"

const char tracee_path[256];

struct event {
	__u32 pstart;
	__u32 pid;
	char tty_name[64];
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct event));
} ringbuff SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * KPROBE for execve.
 */
SEC("ksyscall/execve")
int handler(struct pt_regs *ctx)
{
	struct event *e;
	const char *filename_ptr;
	struct task_struct *task;
	struct signal_struct *sig;
	struct tty_struct *tty;
	char filename[256];
	__u64 pid_tgid;

	/* On x86_64, first arg is a struct pt_regs * pointing to userspace regs */
  struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
  
  /* Read the actual filename pointer from userspace regs */
  bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &regs->di);
  
  /* Now read the string from userspace */
  bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);

  bpf_printk(PNAME" execve: %s\n", filename);

  if (!bpf_strncmp(filename, sizeof(tracee_path), tracee_path)) {
  	e = bpf_ringbuf_reserve(&ringbuff, sizeof(struct event), 0);
  	if (!e)
  		return 0;

  	task = (void *) bpf_get_current_task();
  	bpf_probe_read_kernel(&sig, sizeof(sig), &task->signal);
  	bpf_probe_read_kernel(&tty, sizeof(tty), &sig->tty);
  	bpf_probe_read_kernel_str(e->tty_name, sizeof(e->tty_name), &tty->name);

  	e->pstart = 1;
  	pid_tgid = bpf_get_current_pid_tgid(); 
  	e->pid = pid_tgid >> 32;
  	bpf_get_current_comm(&e->comm, sizeof(e->comm));
  	bpf_ringbuf_submit(e, 0);

  	bpf_override_return(ctx, 1);
  }

  return 0;
}
