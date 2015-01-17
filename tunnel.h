#ifndef TUNNEL_H_   /* Include guard */
#define TUNNEL_H_

#include <netinet/in.h>
#include <stdlib.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <openssl/aes.h>
#include <limits.h>
#include <assert.h>
#include <math.h>

extern int tun_alloc(char *dev, int flags);
extern int in_cksum(u_short *addr, int len);
extern int creatckt_s5();
extern int creatckt_s6();
extern int creatckt_s8();
extern void routerroutine();
extern void router_stage6();
extern void router_stage7();
extern void router_stage8();
extern void router_stage9();
extern void class_AES_set_encrypt_key();
extern void class_AES_set_decrypt_key();
extern void class_AES_encrypt_with_padding();
extern void class_AES_decrypt_with_padding();

struct mycntrlmsg
{
unsigned short circid;
unsigned short portnum;
};
struct mycntrlmsgr
{
unsigned short circid;
};
struct tcp_pseudo
{
__be32 src_addr;
__be32 dest_addr;
u_int8_t reserved;
u_int8_t protocol;
u_int16_t tcplen;
};


struct tupple
{
	__be32 src_addr;
	__be32 dest_addr;
	u_int8_t protocol;
	int src_port;
	int dest_port;
};

struct incmidtup
{
	__be32 src_addr;
	__be32 dest_addr;
	u_int8_t protocol;
	int src_port;
	int dest_port;
	int keyref;
	unsigned short incm;
	struct sockaddr_in pv_addr;
};
struct incmlist
{
	struct incmidtup intupple;
	struct incmlist *next;
};
struct tuplist
{
	struct tupple fitupple;
	struct tuplist *next;
};

struct keylist
{
	char keys[6][17];
	struct keylist *nextky;
};

#endif
