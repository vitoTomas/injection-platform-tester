#define __TARGET_ARCH_x86
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PNAME								"DATA INJECTOR P1:"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u8 data[32];
__u32 size = 3; 


/*
 * Data injector UPROBE for modifying user memory data
 * referenced by user pointers passed as function parameters.
 */
SEC("uprobe/dinjector")
int BPF_UPROBE(handler)
{
	void *regval;
	/*
	 * Using a local size variable for verifier's sanity.
	 */
	__u32 lsize = 1;

	/*
	 * Assume parameter carries a pointer to user-space
	 * memory location.
	 */
	regval = (void *) PT_REGS_PARM1(ctx);
	if (!regval) {
		bpf_printk(PNAME" BPF triggered. Size of data %d\n", size);
		return 0;
	}

	/*
	 * Ensure that at least 1 byte is set with maximum of 32 bytes.
	 */
	size &= (1 << 5) - 1;
	lsize = size;
	lsize = lsize | 1;

	bpf_printk(PNAME" BPF triggered. Size of data %d\n", lsize);
	bpf_probe_write_user(regval, (const void *) data, lsize);
	return 0;
}
