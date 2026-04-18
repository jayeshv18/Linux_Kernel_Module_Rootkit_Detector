#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h> //netwroking socket 
#include <linux/netlink.h>

#define MAX_PAYLOAD 1024  //In User Space, you don't have kernel macros like nlmsg_new. You have to allocate the memory manually.

/* PF_ stands for Protocol Family (used when opening the socket), and AF_ stands for Address Family (used when configuring the sockaddr structures).
 * Under the hood, the compiler defines them as the exact same integer, so our code will compile perfectly.
 * But still code discipline matters in kernel.
 */

int main() {
    /*socket() function in C is used to create a communication endpoint,
    returning a socket descriptor (a non-negative integer) that acts like a file handle for network operations.*/
    int sock=socket(AF_NETLINK, SOCK_RAW, 31); //SOCK_RAW socket type provides direct access to lower-level network protocols and interfaces by bypassing the normal transport layer (TCP/UDP)
    //PF_NETLINK is the protocol family constant used when calling the socket() function to create a Netlink.
    //It provides a full-duplex communication link between kernel modules and user-space processes, acting as a more flexible alternative to ioctl, system calls, or the proc filesystem.

    struct sockaddr_nl addr; //declares a variable to hold the address information for a Netlink socket
    addr.nl_family=AF_NETLINK;
    addr.nl_pid=getpid(); // we have to get the pid of this program so the kernel knows whom to send.
    addr.nl_groups = 0; //we also want to explicitly zero out the multicast groups so the socket knows this is a 1-to-1 connection.

    //bind() function is used to assign a local identity (a "name") to our socket. Without it, our socket exists in the system but has no specific address where it can receive messages.
    bind(sock, (struct sockaddr *)&addr, sizeof(addr)); //It tells the kernel, "I am Process X, and if you have a message for me, send it to this socket"

    struct sockaddr_nl dest_addr; // destination ie the kernel
    dest_addr.nl_family=AF_NETLINK;
    dest_addr.nl_pid=0; // 0 is kernel pid
    dest_addr.nl_groups=0; //unicast, only the kernel can send.

/*It is perfectly fine to use AF_NETLINK in our socket() call,
 *but standard UNIX discipline usually puts PF_NETLINK in socket() and AF_NETLINK in the sockaddr structs.*/

    struct nlmsghdr *nlh = NULL; //Declare a pointer to a Netlink header
    nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD)); //NLMSG_SPACE is a helper macro in C used to calculate the total buffer size required to store a Netlink message
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD)); //Zero out that newly allocated memory using memset to flush garbage.
    nlh->nlmsg_len=NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid=getpid();
    nlh->nlmsg_flags=0;

    //A Netlink message is structured with a header (struct nlmsghdr) followed immediately by the payload.
    strcpy(NLMSG_DATA(nlh), "KNOCK");

    /*Now we have to hand it to the Linux kernel.
     *The sendmsg() and recvmsg() system calls in C don't accept raw data pointers. They require the data to be packaged inside two very specific,
     *highly optimized structures: an I/O Vector (struct iovec) and a Message Header (struct msghdr).
     *Think of the iovec as a forklift pallet, and the msghdr as the shipping manifest.
     */

    struct iovec iov;
    struct msghdr msg;

    iov.iov_base=(void *)nlh; //Set iov.iov_base to your Netlink header pointer (void *)nlh
    iov.iov_len=nlh->nlmsg_len; //our header's length

    memset(&msg,0,sizeof(msg));
    msg.msg_name=(void *)&dest_addr; //point to our destination address
    msg.msg_namelen=sizeof(dest_addr);
    msg.msg_iov=&iov; //point to our pallet
    msg.msg_iovlen=1; //since we only have one pallet

    sendmsg(sock, &msg, 0); //fire the packet down the pipe
    printf("Sendmsg attempted!\n");

    while (1) {
        ssize_t val= recvmsg(sock, &msg, 0); //This function will permanently block and wait until the kernel fires an sk_buff back up the pipe
        //When it catches something, use a printf to display the payload.
        //We can extract the string the exact same way we wrote it: (char *)NLMSG_DATA(nlh).
        if (val > 0) {
            // Print the payload in bold red text, then reset the color
            printf("\033[1;31m[CRITICAL ALERT]\033[0m %s\n", (char *)NLMSG_DATA(nlh));
        } else {
            printf("[-] Error occurred: %zd\n", val);
        }
    }
}
