#define __TARGET_ARCH_x86
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

unsigned page_size;

void *base_page_size(void *pc) {
	uintptr_t address = (uintptr_t)pc;
	uintptr_t mask = ~((uintptr_t)page_size - 1);
  return (void *)(address & mask);
}

SEC("uprobe/adder")
int BPF_UPROBE(handler, int a, int b)
{
	void *page_address;
	void *pc = (void *)PT_REGS_IP(ctx);
	void *bp = (void *)PT_REGS_FP(ctx);
	int val = 20;
	
	page_address = base_page_size(pc);

	bpf_printk("BPF triggered. Passed parameters are %d and %d. " \
	           "Program counter is %p, base page address is %p " \
	           "with page size %u B\n", a, b,  pc, page_address, page_size);
	bpf_probe_write_user(bp - 0x8, &val, sizeof(int));
	return 0;
}
