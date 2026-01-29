#define __TARGET_ARCH_x86
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PNAME				"SINGAL ROUTINE"
#define SIGSTOP			19

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Signal routine UPROBE for parameter or code injection.
 */
SEC("uprobe/signal_routine")
int BPF_UPROBE(handler)
{
	bpf_printk(PNAME" Signal routine fired!\n");
	bpf_send_signal(SIGSTOP);

	return 0;
}
