#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf.h>

#define PATH "/home/vito/injection-platform-tester/official/injection-platform-tester/build/test"
#define PATH_MAX	256UL
#define DATA_MAX	32
#define PID_ANY		-1

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
	(void) level;

	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	struct bpf *skel;
	struct bpf_link *link;
	char path[PATH_MAX];
	unsigned long long sym_addr = 0x1150;
	char data[32];
	int32_t data_length = 0;
	int err;

	if (argc != 5) {
		printf("%s use: [PATH_TO_ELF] [FUNC_SYM_ADDR] [DATA_LEN_BYTES] [DATA]\n",
		       argv[0]);
		return 1;
	}

	memset(data, 0, sizeof(data));
	strncpy(path, argv[1], PATH_MAX);
	sym_addr = (unsigned long long) strtoll(argv[2], NULL, 16);
	data_length = (int32_t) strtol(argv[3], NULL, 10);
	strncpy(data, argv[4], DATA_MAX);

	printf("**** LOADING PROBE ****\n");
	printf("**** ELF: %s\n", path);
	printf("**** SYM ADDR: 0x%llx\n", sym_addr);
	printf("**** DATA: %x\n", data[0]);
	printf("**** DATA LEN: %d\n", data_length);

	/*
	 * Set up libbpf errors and debug info callback.
	 */
	libbpf_set_print(libbpf_print_fn);

	/*
	 * Open BPF application.
	 */
	skel = bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/*
	 * Load BPF program data.
	 */
	memcpy(skel->bss->data, data, data_length);
	skel->data->size = data_length;

	/*
	 * Load and verify BPF programs.
	 */
	err = bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton.\n");
		goto cleanup;
	}

	/*
	 * Attach probe handler
	 */
	link = bpf_program__attach_uprobe(skel->progs.handler,
	                                  false,
	                                  PID_ANY,
	                                  PATH,
	                                  sym_addr);
	if (!link) {
    fprintf(stderr, "Failed to attach uprobe manually.\n");
    goto cleanup;
  }

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing"
	       "/trace_pipe` to see output of the BPF programs.\n");
	printf("Press Ctrl+C to terminate.");

	/*
	 * Wait for SIGINT from user. Upon program termination, BPF
	 * will be destroyed automatically.
	 */
	while (true) {
		sleep(1);
	}

cleanup:
	bpf__destroy(skel);
	return -err;
}
