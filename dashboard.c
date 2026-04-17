#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
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
}