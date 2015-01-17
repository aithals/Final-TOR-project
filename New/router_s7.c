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

#include "tunnel.h"
#include "key.h"

	static int keydetect=0;
	static int cktdetect=0;
	static unsigned short incmid=0;
	unsigned short inocmid;
	unsigned char myyykey[16];
	struct sockaddr_in pvaddr;
void router_stage7(int newsockfd1,int nrot,FILE *rouf2,int rawfd,struct sockaddr_in gserv_addr,char ipadd[],struct sockaddr_in rawtcp_addr,int rawtcpfd)
{
	inocmid=incmid;
	char recbuf[1500];
	bzero(recbuf,1500);
	struct sockaddr_in recv_addr,sender_addr;
	socklen_t clilen=sizeof(struct sockaddr_in);
	static unsigned char myykey[16];
	unsigned char *temkey;
	static struct sockaddr_in prev_addr;
	//static unsigned char myykey[16];
	unsigned short myid=htons((nrot * 256) +1);
	//static unsigned short incmid;
	static int nexthop=0;
	unsigned char *contents;
	AES_KEY enc_key;
	AES_KEY dec_key;
	unsigned char *crypt_text;
	int crypt_text_len;
	unsigned char *clear_crypt_text;
	int clear_crypt_text_len;
	static char ack[4]="ACK";
	int rv = recvfrom(newsockfd1, recbuf, sizeof(recbuf), 0, (struct sockaddr *)&recv_addr, &clilen);
	if (rv > 0)
	{
		char *typek= (char*) (recbuf + sizeof(struct iphdr));

		if(*typek==0x65)
		{
			if(keydetect==0)
			{
				memset(myykey, '\0', sizeof(myykey));
				temkey = (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				printf("%d router:my keys is: %s\n",nrot,temkey);
				strncpy((char*)myykey,(char*)temkey,16);
				printf("%d router:my keys in myykey is: %s\n",nrot,myykey);
				strncpy((char*)myyykey,(char*)myykey,16);
				struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
				fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*typek,msg->circid);
				fflush(rouf2);
				unsigned char *contents = (unsigned char *) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				int i;
				for(i=0;i<(rv-23);i++)
				{
					//fprintf(rouf2,"%x",temp[i]);
					fprintf(rouf2,"%x",*contents);contents++;
					fflush(rouf2);
				}
				fprintf(rouf2,"\n");
				fflush(rouf2);
				fprintf(rouf2,"fake-diffie-hellman, new circuit incoming: 0x%02x, key: ",ntohs(msg->circid));
				fflush(rouf2);
				contents = (unsigned char *) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				for(i=0;i<(rv-23);i++)
				{
					//fprintf(rouf2,"%x",temp[i]);
					fprintf(rouf2,"%x",*contents);contents++;
					fflush(rouf2);
				}
				fprintf(rouf2,"\n");
				fflush(rouf2);
				incmid=msg->circid;
				inocmid=incmid;
				keydetect=1;
				prev_addr=recv_addr;
				pvaddr=prev_addr;

				if (sendto(newsockfd1, ack, sizeof(ack), 0, (struct sockaddr *)&prev_addr, clilen) < 0) {
					perror("sendto failed");
					return;
				}
			}
			else
			{
				/*decrypt and forward*/
				struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
				temkey = (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				printf("%d router:forwarding key:key before decryption is %s len is %d\n",nrot,temkey,rv-23);

				//struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
				fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*typek,msg->circid);
				fflush(rouf2);
				unsigned char *contents = (unsigned char *) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				int i;
				for(i=0;i<(rv-23);i++)
				{
					//fprintf(rouf2,"%x",temp[i]);
					fprintf(rouf2,"%x",*contents);contents++;
					fflush(rouf2);
				}
				fprintf(rouf2,"\n");
				fflush(rouf2);
				class_AES_set_decrypt_key(myykey, &dec_key);
				class_AES_decrypt_with_padding(temkey,rv-23, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
				printf("%d router:forwarding key:key after decryption is %s cryplen is %d \n",nrot,clear_crypt_text,clear_crypt_text_len);
				int j=0;unsigned char keybuffer[1000];
				memset(keybuffer,0,sizeof(keybuffer));
				strncpy((char*)keybuffer,(char*)clear_crypt_text,clear_crypt_text_len);
				while(j<clear_crypt_text_len)
				{
					recbuf[j+23]=*clear_crypt_text;
					j++;clear_crypt_text++;
				}
				fprintf(rouf2,"fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x, key: ",ntohs(msg->circid));
				for(j=0;j<clear_crypt_text_len;j++)
				{
					fprintf(rouf2,"0x%02x",recbuf[j+23]);
					fflush(rouf2);
				}
				fprintf(rouf2,"\n");
				fflush(rouf2);
				sender_addr.sin_family = AF_INET;
				sender_addr.sin_addr.s_addr = htonl(INADDR_ANY);
				sender_addr.sin_port=nexthop;
				msg->circid=myid;
				if (sendto(newsockfd1, recbuf, 23+clear_crypt_text_len, 0, (struct sockaddr *)&sender_addr, clilen) < 0) {
					perror("sendto failed");
					return;
				}
				int rvm = recvfrom(newsockfd1, ack, sizeof(ack), 0, (struct sockaddr *)&recv_addr, &clilen);
				if (rvm > 0)
				{
					if (sendto(newsockfd1, ack, sizeof(ack), 0, (struct sockaddr *)&prev_addr, clilen) < 0) {
						perror("sendto failed");
						return;
					}
				}

			}


		}
		if(*typek==0x62)
		{

			if(cktdetect==0)
			{
			printf("%d router,confirming my key is: %s\n",nrot,myykey);
			char *type= (char*) (recbuf + sizeof(struct iphdr));
			struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
			incmid=msg->circid;
			contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
			fprintf(rouf2,"pkt from port: %d, length: %d, contents:0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*typek,msg->circid);
			fflush(rouf2);
			int i;
			for(i=0;i<(rv-23);i++)
			{
				//fprintf(rouf2,"%x",temp[i]);
				fprintf(rouf2,"%x",*contents);contents++;
				fflush(rouf2);
			}
			fprintf(rouf2,"\n");
			fflush(rouf2);
			contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));

			printf("%d router,before decryption portnum is %s,len is %d\n",nrot, contents,rv-23);
			class_AES_set_decrypt_key(myykey, &dec_key);
			class_AES_decrypt_with_padding(contents,rv-23, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
			printf("%d router,after decryption portnum is %s,len is %d\n",nrot, clear_crypt_text,clear_crypt_text_len);
			nexthop=atoi((char*)clear_crypt_text);
			printf("%d router:portnum in host byte order is %d\n",nrot, ntohs(nexthop));
			cktdetect=1;
			*type=0x63;
			fprintf(rouf2,"new extend circuit: incoming: 0x%02x, outgoing: 0x%02x, at %d\n",ntohs(msg->circid),ntohs(myid),ntohs(nexthop));
			fflush(rouf2);
			if (sendto(newsockfd1, recbuf, 23, 0, (struct sockaddr *)&prev_addr, clilen) < 0) {
				perror("sendto failed");
				return;
				}
			}
			else
			{
				struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
				unsigned char keybuffer[1000];
				memset(keybuffer,'\0',sizeof(keybuffer));
				int j=0;
				fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*typek,msg->circid);
				fflush(rouf2);
				contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				int i;
				for(i=0;i<(rv-23);i++)
				{
					//fprintf(rouf2,"%x",temp[i]);
					fprintf(rouf2,"%x",*contents);contents++;
					fflush(rouf2);
				}
				fprintf(rouf2,"\n");
				fflush(rouf2);
				printf("%d router: length of the content is %d\n",nrot,rv-23);
				contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				class_AES_set_decrypt_key(myykey, &dec_key);
				class_AES_decrypt_with_padding(contents,rv-23, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
				strncpy((char*)keybuffer,(char*)clear_crypt_text,clear_crypt_text_len);
				printf("%d router:encrypted portlen after decryption is %d : strlen %d \n",nrot,clear_crypt_text_len, strlen((char*)clear_crypt_text));
				printf("%d router:encrypted port after decryption is %s \n",nrot,clear_crypt_text);
				while(j<clear_crypt_text_len)
				{
					recbuf[j+23]=*clear_crypt_text;
					j++;clear_crypt_text++;
				}
				fprintf(rouf2,"forwarding extend circuit: incoming: 0x%02x, outgoing: 0x%02x at %d\n",ntohs(msg->circid),ntohs(myid),ntohs(nexthop));
				fflush(rouf2);
				sender_addr.sin_family = AF_INET;
				sender_addr.sin_addr.s_addr = htonl(INADDR_ANY);
				sender_addr.sin_port=nexthop;
				msg->circid=myid;
				if (sendto(newsockfd1, recbuf, 23+clear_crypt_text_len, 0, (struct sockaddr *)&sender_addr, clilen) < 0) {
					perror("sendto failed");
					return;
				}
				rv = recvfrom(newsockfd1, recbuf, sizeof(recbuf), 0, NULL, NULL);
				if (rv > 0)
				{	char *type= (char*) (recbuf + sizeof(struct iphdr));
					struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
					fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x\n",ntohs(recv_addr.sin_port),(rv-20),*type,msg->circid);
					fflush(rouf2);
					fprintf(rouf2,"forwarding extend-done circuit, incoming:0x%02x, outgoing: 0x%02x at %d\n",ntohs(myid),ntohs(incmid),ntohs(prev_addr.sin_port));
					msg->circid=incmid;
					if (sendto(newsockfd1, recbuf, 23, 0, (struct sockaddr *)&prev_addr, clilen) < 0) {
						perror("sendto failed");
						return;
						}
				}
			}

		}
		else if(*typek==0x61)
		{
			if (nexthop == 0xffff)
			{
				struct sockaddr_in out_addr;
				struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
				unsigned char keybuffer[1000];
				memset(keybuffer,'\0',sizeof(keybuffer));
				//int j=0;
				fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*typek,msg->circid);
				fflush(rouf2);
				contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				int i;
				for(i=0;i<(rv-23);i++)
				{
					//fprintf(rouf2,"%x",temp[i]);
					fprintf(rouf2,"%x",*contents);contents++;
					fflush(rouf2);
				}
				fprintf(rouf2,"\n");
				fflush(rouf2);
				contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				printf("%d router: length of the content is %d\n",nrot,rv-23);
				class_AES_set_decrypt_key(myykey, &dec_key);
				class_AES_decrypt_with_padding(contents,rv-23, &clear_crypt_text, &clear_crypt_text_len, &dec_key);

				struct iphdr *ip=(struct iphdr*)(clear_crypt_text);
				struct tcphdr *tcp;
				struct icmphdr *icmp;
				if(ip->protocol == IPPROTO_TCP)
				{
					tcp=(struct tcphdr*)(clear_crypt_text+sizeof(struct iphdr));
				printf("TCP dst port is %d ip+icmp=%d\n",tcp->dest,clear_crypt_text_len);
				}
				else
				{
					icmp=(struct icmphdr*)(clear_crypt_text+sizeof(struct iphdr));
				}

				//struct tcphdr *tcp=(struct tcphdr*)(clear_crypt_text+sizeof(struct iphdr));
				//struct iphdr *ip=(struct iphdr*)(clear_crypt_text);
				//printf("TCP dst port is %d ip+icmp=%d\n",tcp->dest,clear_crypt_text_len);
				//exit(0);
				printf("sendmsg here\n");
				out_addr.sin_family = AF_INET;
				out_addr.sin_addr.s_addr = ip->daddr;
				//out_addr.sin_port = tcp->dest;
				char tempo1[INET_ADDRSTRLEN];
				char tempo2[INET_ADDRSTRLEN];
				struct in_addr soaddri;
				soaddri.s_addr = ip->saddr;

				inet_ntop(AF_INET, &(out_addr.sin_addr), tempo1, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(soaddri), tempo2, INET_ADDRSTRLEN);
				fprintf(rouf2,"outgoing TCP packet, circuit incoming: 0x%02x, incoming src IP/port:%s:%d, outgoing src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %lu, ackno: %lu\n",ntohs(msg->circid),tempo2,ntohs(tcp->source),ipadd,ntohs(tcp->source),tempo1,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack));
				fflush(rouf2);
				/*fprintf(rouf2,"ICMP from port: %d, src: %s, dst: %s, type: %d\n",ntohs(gserv_addr.sin_port),tempo2,tempo1,icmp->type);
				fflush(rouf2);*/
				//printf("dst address is %s and icmp type is %d \n",tempo1,icmp->type);
				/*checking if the packet is to be forwarded or is meant for the router itself*/
				//exit(0);
				if(strncmp(tempo1,"10.5.51",7)==0)
				{
					printf("sigthu bidu guru\n");
					soaddri.s_addr = ip->saddr;
					ip->saddr=ip->daddr;
					ip->daddr=soaddri.s_addr;
			    	//icmp->type=0;
			    	//icmp->checksum=0;
			/*checksum calculation*/
			    	//int len=rv-20;
			    	//u_short *icm=((u_short *)recbuf+ sizeof(struct iphdr));
			    	//int check=in_cksum(icm,len);
			    	//icmp->checksum = check;

			    	if (sendto(newsockfd1, recbuf, rv, 0, (struct sockaddr *)&prev_addr, sizeof(gserv_addr)) < 0)
					{
						perror("sendto failed");
						exit(0);
					}

				}
				else
				{
				/*soaddr.s_addr = ip->saddr;*/
				/*icmppkt=recbuf+ sizeof(struct iphdr);*/
				/*strncpy(icmppkt,recbuf+ sizeof(struct iphdr),8);
				icmppkt[8]='\0';*/

					inet_pton(AF_INET, ipadd, &(ip->saddr));
					if(ip->protocol == IPPROTO_TCP )
					{
					struct tcp_pseudo pseudo;
					pseudo.dest_addr=ip->daddr;
					pseudo.src_addr=ip->saddr;
					pseudo.reserved=0;
					pseudo.protocol=IPPROTO_TCP;
					pseudo.tcplen=htons(clear_crypt_text_len-20);


					tcp->check=0;
					printf("rawtcp portn num is %d \n",tcp->source);
					//tcp->source=rawtcp_addr.sin_port;
					printf("rawtcp portn num is %d \n",tcp->source);
					char *chksmbuf;
					int csize = sizeof(struct tcp_pseudo) + clear_crypt_text_len-20;
					chksmbuf = malloc(csize);
					memcpy(chksmbuf , (char*) &pseudo , sizeof (struct tcp_pseudo));
					memcpy(chksmbuf + sizeof(struct tcp_pseudo) , tcp , clear_crypt_text_len-20);
			    	u_short *tcpchk=((u_short *)chksmbuf);
			    	int check=in_cksum(tcpchk,csize);

					tcp->check=check;
					}




					printf("%d router:size recvd at last router is %d \n",nrot,rv);
					struct iovec iov[1];/*reference :http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html*/
					int fd=rawfd;
					if(ip->protocol == IPPROTO_TCP )
					{
						fd=rawtcpfd;
						iov[0].iov_base=tcp;
					}
					else
						iov[0].iov_base=icmp;
				iov[0].iov_len=clear_crypt_text_len-20;

				struct msghdr message;
				message.msg_name=&out_addr;
				message.msg_namelen=sizeof(out_addr);
				message.msg_control=0;
				message.msg_controllen=0;
				message.msg_iov=iov;
				message.msg_iovlen=1;
				if (sendmsg(fd,&message,0)==-1) {
					perror("error at sendmsg \n");
							exit(0);
				}
				}
			}
			else
			{
				struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
				msg->circid=myid; unsigned char keybuffer[1000];
				memset(keybuffer,'\0',sizeof(keybuffer));
				fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*typek,msg->circid);
				fflush(rouf2);
				contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				int i;
				for(i=0;i<(rv-23);i++)
				{
					//fprintf(rouf2,"%x",temp[i]);
					fprintf(rouf2,"%x",*contents);contents++;
					fflush(rouf2);
				}
				fprintf(rouf2,"\n");
				fflush(rouf2);
				fprintf(rouf2,"relay encrypted packet, circuit incoming: 0x%02x, outgoing: 0x%02x \n",ntohs(incmid),ntohs(myid));
				fflush(rouf2);
				int j=0;
				contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				printf("%d router: length of the content is %d\n",nrot,rv-23);
				class_AES_set_decrypt_key(myykey, &dec_key);
				class_AES_decrypt_with_padding(contents,rv-23, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
				while(j<clear_crypt_text_len)
				{
					recbuf[j+23]=*clear_crypt_text;
					j++;clear_crypt_text++;
				}
				sender_addr.sin_family = AF_INET;
				sender_addr.sin_addr.s_addr = htonl(INADDR_ANY);
				sender_addr.sin_port=nexthop;
				msg->circid=myid;
				if (sendto(newsockfd1, recbuf, 23+clear_crypt_text_len, 0, (struct sockaddr *)&sender_addr, clilen) < 0) {
					perror("sendto failed");
					return;
				}
			}
			}
		else if(*typek==0x64)
		{
			unsigned char *pts=(unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
			struct mycntrlmsgr *msg = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
			msg->circid=incmid;
			printf("%d router:ip+icmp before enc %s and len is %d\n",nrot,pts,rv-23);
			contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
			fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*typek,msg->circid);
			fflush(rouf2);
			contents= (unsigned char*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
			int i;
			for(i=0;i<(rv-23);i++)
			{
				//fprintf(rouf2,"%x",temp[i]);
				fprintf(rouf2,"%x",*contents);contents++;
				fflush(rouf2);
			}
			fprintf(rouf2,"\n");
			fflush(rouf2);
			fprintf(rouf2,"relay reply encrypted packet, circuit incoming:  0x%02x, outgoing: 0x%02x \n",ntohs(myid),ntohs(incmid));
			fflush(rouf2);


			class_AES_set_encrypt_key(myykey, &enc_key);
			class_AES_encrypt_with_padding(pts,rv-23, &crypt_text, &crypt_text_len, &enc_key);
			int j=0;
			while(j<crypt_text_len)
			{
				recbuf[j+23]=*crypt_text;
				j++;crypt_text++;
			}
			if (sendto(newsockfd1, recbuf, 23+crypt_text_len, 0, (struct sockaddr *)&prev_addr, clilen) < 0) {
					perror("sendto failed");
					exit(0);
			}

		}
		}

		/*put relay data conditions here*/




}

