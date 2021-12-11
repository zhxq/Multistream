/*
 * Adapted from https://github.com/ilammy/ftrace-hook for hook management part.
 */

#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/blkdev.h>
#include <linux/nvme_ioctl.h>
#include <linux/nvme.h>
#include <linux/moduleparam.h>
#include "nvme.h"

// Uncomment the following line to enable logging to dmesg.
//#define DEBUG_MODULE

#ifdef DEBUG_MODULE
#define printdbg(fmt, ...) \
    do { printk(fmt, ## __VA_ARGS__); } while (0)
#define printwmodname(fmt, ...) \
    do { pr_info(fmt, ## __VA_ARGS__); } while (0)
#else
#define printdbg(fmt, ...) \
    do { } while (0)
#define printwmodname(fmt, ...) \
    do { } while (0)
#endif

MODULE_DESCRIPTION("Block IO Stream ID Tagger");
MODULE_AUTHOR("Xiangqun Zhang <xzhang84@syr.edu>");
MODULE_LICENSE("GPL");

// Handle streams argument
// Takes a list like "proc1,proc2;proc3"
//   which will assign I/O from proc1 and proc2 to stream 2
//   and proc3 to stream 3. Stream ID starts from 2 as defined by Linux kernel.
static char* streams = NULL;
static int arg_streams = 0;
static int* arg_stream_processes;
static char*** streamlist = NULL;

static int streams_set(const char *oldval, const struct kernel_param *kp)
{
    char* val;
	int i;
	int j;
	int streamc = 1;
	int processes = 1;
    val = kmalloc(strlen(oldval) + 1, GFP_KERNEL);
	streams = kmalloc(strlen(oldval) + 1, GFP_KERNEL);
    strcpy(val, oldval);
	strcpy(streams, oldval);
	for (i = 0; i < arg_streams; i++){
		for (j = 0; j < arg_stream_processes[i]; j++){
			kfree(streamlist[i][j]);
		}
		kfree(streamlist[i]);
	}
	kfree(arg_stream_processes);
	kfree(streamlist);

	char* tmpstream = val;
	char* tmpprocess;
    char* tmpstream_r = val;
    char* tmpprocess_r;

	// count how many streams we need here
	for (i = 0; val[i] != '\0'; i++){
		if (val[i] == ';'){
			streamc++;
		}
	}
	streamlist = kmalloc_array(streamc, sizeof(char**), GFP_KERNEL);
    arg_streams = streamc;
    arg_stream_processes = kmalloc(sizeof(int) * streamc, GFP_KERNEL);

	streamc = 0;
	while ((tmpstream = strsep(&tmpstream_r, ";"))) {
        printdbg("Stream: %d\n", streamc + 1);
        printdbg("Info: %s\n", tmpstream);
		processes = 1;
		for (i = 0; tmpstream[i] != '\0'; i++){
			if (tmpstream[i] == ','){
				processes++;
			}
		}
		streamlist[streamc] = kmalloc_array(processes, sizeof(char*), GFP_KERNEL);
        arg_stream_processes[streamc] = processes;
		processes = 0;
		tmpprocess = tmpstream;
		tmpprocess_r = tmpstream;
		while ((tmpprocess = strsep(&tmpprocess_r, ","))) {
            printdbg("  Process: %d\n", processes + 1);
            printdbg("  Name: %s\n", tmpprocess);
			streamlist[streamc][processes] = kmalloc(strlen(tmpprocess) + 1, GFP_KERNEL);
			strcpy(streamlist[streamc][processes], tmpprocess);
			processes++;
		}
		streamc++;
	}
	kfree(val);
	return 0;
}

// Find stream ID by process name
static int find_stream(const char* process_name){
    int i, j;
    printdbg("Total streams: %d\n", arg_streams);
    printdbg("Finding %s\n", process_name);
    for (i = 0; i < arg_streams; i++){
        printdbg("Stream %d has %d processes\n", i + 2, arg_stream_processes[i]);
        for (j = 0; j < arg_stream_processes[i]; j++){
            printdbg("  Comparing to: %s\n", streamlist[i][j]);
            if (strcmp(streamlist[i][j], process_name) == 0){
                return i + 2;
            }
        }
    }
    return 0;
}
 
static int stream_get(char* buffer, const struct kernel_param *kp){
	if (streams == NULL) return 0;
	strcpy(buffer, streams);
	return strlen(buffer);
}

static const struct kernel_param_ops param_ops_streams = {
	.set	= streams_set,
	.get	= stream_get,
};

module_param_cb(streams, &param_ops_streams, NULL, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(streams, "Process name list for streams, starting with stream 2. Example: \"a,b,c;d;e,f;g\" means stream 2 for process a,b and c; stream 3 for d; stream 4 for e,f and stream 5 for g. Process not on this list will be not assigned to any stream. Both stream ID = 0 and 1 will not be passed to the device as defined in Linux Kernel.");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static asmlinkage void (*real_blk_account_io_start)(struct request *rq);

static asmlinkage void fh_blk_account_io_start(struct request *rq)
{
	struct gendisk *rq_disk;
	rq_disk = rq->rq_disk;
	printwmodname("blk_account_io_start() before\n");
	printdbg(KERN_INFO "Loading Module\n");
	printdbg("The process id is %d\n", (int) task_pid_nr(current));
	printdbg("The process vid is %d\n", (int) task_pid_vnr(current));
	printdbg("The process group is %d\n", (int) task_tgid_nr(current));
	rq->write_hint = find_stream(current->comm);
	printdbg("Writing to new Disk name: %s", rq_disk->disk_name);
	printdbg("Process name: %s, write_hint: %d, sector: %#llx, data_len: %#x\n", current->comm, rq->write_hint, rq->__sector, rq->__data_len);
	real_blk_account_io_start(rq);
	printwmodname("blk_account_io_start() after\n\n");
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
static asmlinkage blk_status_t (*real_nvme_setup_cmd)(struct nvme_ns *ns, struct request *req, struct nvme_command *cmd);
static asmlinkage blk_status_t fh_nvme_setup_cmd(struct nvme_ns *ns, struct request *req, struct nvme_command *cmd)
#else
static asmlinkage blk_status_t (*real_nvme_setup_cmd)(struct nvme_ns *ns, struct request *req);
static asmlinkage blk_status_t fh_nvme_setup_cmd(struct nvme_ns *ns, struct request *req)
#endif
{
	blk_status_t ret;
	struct gendisk *rq_disk;
	rq_disk = req->rq_disk;
	printwmodname("nvme_setup_cmd() before\n");
	printdbg(KERN_INFO "Loading Module\n");
	printdbg("The process id is %d\n", (int) task_pid_nr(current));
	printdbg("The process vid is %d\n", (int) task_pid_vnr(current));
	printdbg("The process name is %s\n", current->comm);
	printdbg("The process group is %d\n", (int) task_tgid_nr(current));
	printdbg("Process name: %s, write_hint: %d, sector: %#llx, data_len: %#x\n", current->comm, req->write_hint, req->__sector, req->__data_len);
	//printdbg("What can we get from write_hint: %d", req->write_hint);
	#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	ret = real_nvme_setup_cmd(ns, req, cmd);
	#else
	ret = real_nvme_setup_cmd(ns, req);
	#endif
	printwmodname("nvme_setup_cmd() after\n");
	return ret;
}

#define SYSCALL_NAME(name) (name)

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("nvme_setup_cmd",  fh_nvme_setup_cmd,  &real_nvme_setup_cmd),
	HOOK("blk_account_io_start",  fh_blk_account_io_start,  &real_blk_account_io_start),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	printwmodname("module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	printwmodname("module unloaded\n");
}
module_exit(fh_exit);
