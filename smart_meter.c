#include <linux/init.h> //This gives us the special tags needed to mark our constructor and destructor.
#include <linux/kernel.h> //This is the core header that tells the compiler, "Hey, this isn't a normal program; this is a kernel plug-in
#include <linux/module.h> //This gives us access to our megaphone: printk
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/netlink.h> //The Netlink protocol, it acts as a connection between userspace to kernel space to share data
#include <linux/skbuff.h> //Socket Buffers - how Linux packages network data
#include <net/sock.h> //The core socket definitions


// Module metadata (Required, otherwise the kernel might reject it as "tainted")
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayesh V");
MODULE_DESCRIPTION("Smart Meter Telemetry Base Module");
MODULE_VERSION("1.0");

struct sock *nl_sk=NULL; //heavy-duty data structure that represents the network layer of a socket.
//While a standard struct socket is the high-level interface used for system calls, struct sock is the internal engine that handles the actual protocol logic and data buffering.

struct netlink_kernel_cfg netlink_settings={0}; //Settings Menu for our Netlink socket. When we create a Netlink socket in the kernel, we can't just open it; we have to tell the kernel how to behave when it receives messages. This structure holds those instructions.
int user_space_pid = 0; // We need a global variable to store the PID
static struct kprobe exec_trap;//In C, the kernel uses a structure to define the trap. We define this globally (outside of any function) so both our init and exit functions can see it.
//When a kprobe triggers, it looks for a specific function attached to it called a pre_handler (because it runs before the original function executes).
// This is the function that runs every time the tripwire is hit

static int my_hook_function(struct kprobe *p, struct pt_regs *regs) { //The kernel dictates exactly what this function must look like. It always takes two arguments: a pointer to the trap itself, and a pointer to the CPU registers

    struct sk_buff *skb = NULL; //take some pace or create space in a sk_buff from the kernel, you use specific kernel functions to shift the internal pointers (data and tail).

    /* * The 'current' macro is a magical global pointer provided by <linux/sched.h>.
     * It ALWAYS points to the task_struct (the DNA) of the process currently
     * running on the CPU. Because this process just asked the CPU to execute
     * a new command, 'current' is our suspect.
     * * current->pid  : The Process ID (integer)
     * current->comm : The short name of the executable (string)
     */
     //current_uid().val gives us which user id is executing the program or command. 0= root

    //Privilege Escalation Check
    // 1. Extract the UID
    int user_id=current_uid().val;
    // 2. Trap 1: Privilege Escalation Check
    if (user_id==0) {
        // We only scream if UID is 0 (Root)

        skb=nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);//To allocate a sk_buff big enough to hold a Netlink message, we should use nlmsg_new(). This helper automatically calculates the extra space needed for the Netlink header and required alignment padding
        if (user_space_pid==0) { // no one is listening, printing as backup
            printk(KERN_INFO "ROOTKIT DETECTED: ROOT PRIVILEGE EXECUTION CAUGHT: PID [%d] running [%s]\n",current->pid,current->comm );
            kfree_skb(skb); //free mem
        }else {
            const char *alert = "ROOTKIT DETECTED!";
            int payload_len = strlen(alert) + 1;
            struct nlmsghdr *nlh=nlmsg_put(skb,0,0,NLMSG_DONE,payload_len,0);
            strncpy(nlmsg_data(nlh), alert, payload_len);
            netlink_unicast(nl_sk, skb, user_space_pid,MSG_DONTWAIT);

        }
    }

    //DKOM trap
    int is_found=0; //flag to check match
    struct task_struct *task; // inbuilt struct for task in kernel
    for_each_process(task) { //for_each_process is a macro that expands into a standard for loop in the Linux kernel.
        //It is used by kernel developers and rootkits to traverse the circular doubly-linked list of all running tasks.
        if (task->pid == current->pid) { // if current pid and pid in task matches while looping then the flag is 1 stating that we found a match
            is_found=1;
            break; // after match found immediately break to save cpu costs.
        }
    }

    if (is_found==0) { // if still match not found even after looping through the tasks then the pid has been removed i.e the rootkit is active.
        skb=nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);//To allocate a sk_buff big enough to hold a Netlink message, we should use nlmsg_new(). This helper automatically calculates the extra space needed for the Netlink header and required alignment padding

        if (user_space_pid==0) { // no one is listening, printing as backup
            printk(KERN_INFO "ROOTKIT DETECTED: ROOT PRIVILEGE EXECUTION CAUGHT: PID [%d] running [%s]\n",current->pid,current->comm );
            kfree_skb(skb); //free mem
        }else {
            const char *alert = "GHOST DETECTED!";
            int payload_len = strlen(alert) + 1;
            struct nlmsghdr *nlh=nlmsg_put(skb,0,0,NLMSG_DONE,payload_len,0);
            strncpy(nlmsg_data(nlh), alert, payload_len);
            netlink_unicast(nl_sk, skb, user_space_pid,MSG_DONTWAIT);

        }
    }
    /*
     * We MUST return 0 here.
     * Returning 0 tells the kernel: "I am done observing. Please allow the
     * original __x64_sys_execve function to proceed normally."
     * (If we returned a non-zero value, we would accidentally block the program from launching!)
     */

    // 3. Let the original program run
    return 0; // Return 0 to let the original program continue running
}

// The Constructor (runs the moment the module is loaded)
static int __init start_init(void) { //we write a function and don't declare it as static, the C compiler assumes us want this function to be public and shared with the entire rest of the operating system.
    //Since our constructor and destructor are only meant to be used by our specific module locally, we need to lock them down.
    // printk is the kernel's megaphone. KERN_INFO is the log level.
    printk(KERN_INFO "Module plug-in successful... Monitoring kernel.\n");
    // A return of 0 tells the OS the module loaded successfully.

    //passing this to kernel. NETLINK_USERSOCK is explicitly reserved for user-space to user-space communication
    //we have to only initialize this once, If you put netlink_kernel_create inside your execve hook, you are telling the kernel to build a completely new network socket every single time any process on the system runs a command.
    //The kernel will instantly run out of networking resources and crash.
    nl_sk=netlink_kernel_create(&init_net,NETLINK_USERSOCK,&netlink_settings); //the primary function used within a Linux kernel module to establish a communication channel (a socket) with user-space applications
    if (nl_sk==NULL) {
        printk(KERN_INFO "Failed creating netlink socket.\n");
        return -1;
    }

    /* THIS NOTE IS FOR THE DEVELOPERS BETTER UNDERSTANDING
        so here now we have to spy on the kernel what  is doing... so for that the ftrace is used to look at the kernel what it is doing.
        then every process is made through a function called execvp and in kernel the call is named as __x64_sys_execve function.
        now this __x64_sys_execve carries out the call and process... so this means that we need to have a look and spy this __x64_sys_execve.
        which means we have to make a trap for __x64_sys_execve before it is executed and make them pass through the trap, the trap will trigger if it finds a hidden call typical rootkit behaviour.
        so now to interrupt means to make a trap we need kprobes thats the way to interrupt kernel, so we'll activate the kprobes algorithm, Call the kernel's register_kprobe function.

        Check if it returns an error (a value less than 0).
        If it fails, print an error and abort the module load.
        If it succeeds, print a success message.

        When our module is unloaded, we must disarm the trap. If we forget to do this, the kernel will try to run our hook function after our module has been deleted from memory, resulting in an instant Kernel Panic.

        Algorithm: Call the kernel's unregister_kprobe function.
        Print a message saying the tripwire is disarmed.

        the simple analogy is used is tripwire thing.
    */

    exec_trap.symbol_name = "__x64_sys_execve"; // The target door
    exec_trap.pre_handler = my_hook_function;   // The bell to ring
    int res=register_kprobe(&exec_trap); /*install a kernel probe (kprobe), a dynamic instrumentation mechanism that allows us to "hook" almost any instruction in the running kernel without needing to rebuild or reboot the system*/
    //This function returns an integer. 0 means success, anything negative means it failed.
    if (res==0) {
        printk(KERN_INFO "Module plug-in successful...\n");
        list_del(&THIS_MODULE->list);  //The Linux kernel provides a highly dangerous, built-in function to sever these chains called list_del(). It takes exactly one argument: the memory address of the list you want to delete.
        return res;
    }else{
        printk(KERN_INFO "Module plug-in failed...\n");
        return res;
    }

    return 0;
}

// The Destructor (runs the moment the module is removed)
static void __exit end_exit(void) {
    netlink_kernel_release(nl_sk); //Before we exit, we must clean up the socket using netlink_kernel_release(), passing it our global socket pointer.
    unregister_kprobe(&exec_trap);
    printk(KERN_INFO "All the used memory and allocations are freed, Turning off monitoring module...\n");
}

// Registering the functions with the kernel so it knows which is which
module_init(start_init);
module_exit(end_exit);