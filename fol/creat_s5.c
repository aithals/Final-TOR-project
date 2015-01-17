#include <stdlib.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>

#include "tunnel.h"

int creatckt_s5(int sockfd,int nrot,int nhops,struct sockaddr_in cli_addr[],FILE *prof1)
{
	socklen_t clilen=sizeof(struct sockaddr_in);
	struct sockaddr_in recv_addr;
	printf("at ckt create sending to first router\n");
	//char *buffert="router ge bandhee maga??";
	int hopsel[nhops];
	int i=0,j=0;
	srand(time(NULL));
	for(i=0;i<nhops;i++)
	{
randomagain:hopsel[i]=rand() % nrot;
		if(i==0)
		{
			printf("%d \n ",hopsel[i]);
			fprintf(prof1,"hop: %d, router: %d\n",i+1,hopsel[i]+1);
			fflush(prof1);
			continue;
		}
		for(j=i-1;j>=0;j--)
		{
			if(hopsel[i]==hopsel[j])
				goto randomagain;

		}
		printf("%d \n ",hopsel[i]);
		fprintf(prof1,"hop: %d, router: %d\n",i+1,hopsel[i]+1);
		fflush(prof1);
	}
	for(i=0;i<nhops;i++)
	{
	char msgbuf[25];
	char recbuf[23];
	memset(msgbuf,0,sizeof(msgbuf));
	struct in_addr addr;
	struct iphdr *ip = (struct iphdr*) msgbuf;
	inet_pton(AF_INET, "127.0.0.1", &addr);
	ip->daddr=addr.s_addr;
	ip->saddr=addr.s_addr;
	ip->protocol=253;
	char *type= (char*) (msgbuf + sizeof(struct iphdr));
	*type=0x52;
	struct mycntrlmsg *msg = (struct mycntrlmsg*) (msgbuf + sizeof(struct iphdr)+1);
	msg->circid=htons(0x01);
	if(i<(nhops-1))
	{
	msg->portnum=(cli_addr[hopsel[i+1]].sin_port);/*has to be in network byte order*/
	}
	else
		msg->portnum=0xffff;

	printf("Proxy:portn num %d, size : %d \n",msg->portnum,sizeof(msgbuf));

	if (sendto(sockfd, msgbuf, sizeof(msgbuf), 0, (struct sockaddr *)&cli_addr[hopsel[0]], clilen) < 0) {
		perror("sendto failed");
		return 0;
	}
	int rv = recvfrom(sockfd, recbuf, sizeof(recbuf), 0, (struct sockaddr *)&recv_addr, &clilen);
	if (rv > 0)
	{
		ip = (struct iphdr*) recbuf;
		type= (char*) (recbuf + sizeof(struct iphdr));
		struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
		fprintf(prof1,"pkt from port: %d, length: 3, contents: 0x%02x%04x\n",ntohs(recv_addr.sin_port),*type,msgr->circid);
		fprintf(prof1,"incoming extend-done circuit, incoming: 0x%02x from port: %d\n",ntohs(msg->circid),ntohs(recv_addr.sin_port));
		fflush(prof1);
	}
	}
	return hopsel[0];
}
