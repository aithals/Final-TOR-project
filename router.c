
#include "tunnel.h"

void error(const char *msg)
{
    perror(msg);
    exit(0);

}

extern int pktsent;

extern unsigned char myyykey[16];/*for stage 6 ,7 and 9*/
extern unsigned char myyykey8[6][16];/*for stage 8 only*/
extern unsigned short inocmid;/*for stage 7 only*/

extern struct sockaddr_in pvaddr;
extern struct incmlist *listtt;
void routerroutine(int a[], int nrot, struct sockaddr_in gserv_addr,char ipadd[])
{




	int newsockfd1, rawfd, rawtcpfd;
	struct sockaddr_in cli_addr1,raw_addr,out_addr, sender_addr,back_addr, rawtcp_addr;
	struct in_addr soaddr;
	unsigned short newid=0;
	unsigned short nexthop;
	unsigned short incmid;
	FILE *rouf2;
	char *mode = "w";
	char fil2[20];
	sprintf(fil2,"stage%d.router%d.out",a[0],nrot);/*creating output file for router according to stage and the router number*/
	rouf2 = fopen(fil2,mode);
	int gpid=getpid();
	int rv,rvm;
	char recbuf[2000];
	bzero(recbuf,2000);
	newsockfd1 = socket(AF_INET, SOCK_DGRAM, 0);/*udp port for router*/
	if (newsockfd1 < 0)
	error("ERROR opening socket");

	cli_addr1.sin_family = AF_INET;
	cli_addr1.sin_addr.s_addr = htonl(INADDR_ANY);
	cli_addr1.sin_port = 0;
	bind(newsockfd1, (struct sockaddr *)&cli_addr1, sizeof(cli_addr1));
	socklen_t clen = sizeof(cli_addr1);
	getsockname(newsockfd1, (struct sockaddr *)&cli_addr1, &clen);
	fprintf(rouf2,"router: %d, pid: %d, port: %d ",nrot,gpid,ntohs(cli_addr1.sin_port));
	fflush(rouf2);
	if(a[0]>=5)
	{
		fprintf(rouf2,"IP: %s\n",ipadd);
		fflush(rouf2);
	}
	else
	{
		fprintf(rouf2,"\n");
		fflush(rouf2);
	}
	char *buffer="im up";
	sleep(0.5);
	if(sendto(newsockfd1, buffer, strlen(buffer), 0, (struct sockaddr *)&gserv_addr, sizeof(gserv_addr)) < 0)
	{
		perror("sendto failed");
		exit(0);
	}

	/*start of raw socket*/
	char icmppkt[1500];
	rawfd= socket(AF_INET, SOCK_RAW,IPPROTO_ICMP);
	if (rawfd==-1) {
	perror("socket creation failed");
	exit(0);
	}
	raw_addr.sin_family = AF_INET;
	inet_pton(AF_INET, ipadd, &(raw_addr.sin_addr));
	raw_addr.sin_port = 0;
	bind(rawfd,(struct sockaddr *)&raw_addr, sizeof(raw_addr));

	/*raw sock creation ends here*/

	/*raw socket for tcp*/
	rawtcpfd= socket(AF_INET, SOCK_RAW,IPPROTO_TCP);
	if (rawtcpfd==-1) {
	perror("socket creation failed");
	exit(0);
	}
	rawtcp_addr.sin_family = AF_INET;
	inet_pton(AF_INET, ipadd, &(rawtcp_addr.sin_addr));
	rawtcp_addr.sin_port = 0;
	bind(rawtcpfd,(struct sockaddr *)&rawtcp_addr, sizeof(rawtcp_addr));
	//getsockname(rawtcpfd, (struct sockaddr *)&rawtcp_addr, &clen);

	/*raw socket for tcp ends*/

	/*provisioning select function*/
	fd_set readfds;
	int maxfd;
	if(rawfd > newsockfd1)
	{
	if(rawfd>rawtcpfd)
		maxfd = rawfd;
	else
		maxfd = rawtcpfd;
	}
	else
	{
	if(newsockfd1>rawtcpfd)
		maxfd = newsockfd1;
	else
		maxfd = rawtcpfd;
	}
	maxfd++;int selval;


	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	/*ICMP forward using raw socket and sendmsg()*/
	/*also make sure that you check for "10.5.51" and decide to send it out to the real world or reply locally*/
	while(1)
	{
		FD_ZERO(&readfds);
		FD_SET(newsockfd1, &readfds);
		FD_SET(rawfd, &readfds);
		FD_SET(rawtcpfd, &readfds);
		if ((selval=select(maxfd , &readfds, NULL, NULL,&tv ) )== -1){
		perror("select error");
		}
		else if(selval==0)
		{
			if(a[0]==9)
			{
				if(pktsent==1)
				{
					printf("timeout at router %d\n",nrot);
					fprintf(rouf2,"time out no reply from next router\n");
					fflush(rouf2);

					exit(0);
					/*have to send back some msg*/
				}
			}
			continue;
		}
		else
		{
			if( FD_ISSET(newsockfd1,&readfds))
			{
				/*make sure to check  which stage before you proceed*/
										/*if(a[0]==5) do cktcreation steps*/


				/*Common code for all stages till here*/
				if(a[0]==8)
				{
					printf("going to stage 8\n");
					router_stage8(newsockfd1,nrot,rouf2,rawfd,gserv_addr,ipadd,rawtcp_addr,rawtcpfd);
				}
				if(a[0]==7)
				{
					printf("going to stage 7\n");
					router_stage7(newsockfd1,nrot,rouf2,rawfd,gserv_addr,ipadd,rawtcp_addr,rawtcpfd);
				}
				if(a[0]==9)
				{
					printf("going to stage 9\n");
					router_stage9(newsockfd1,nrot,rouf2,rawfd,gserv_addr,ipadd,rawtcp_addr,rawtcpfd);
				}

				if(a[0]==6)
				{
					printf("going to stage 6\n");
					router_stage6(newsockfd1,nrot,rouf2,rawfd,gserv_addr,ipadd);
				}


				/*stage 5 code for messages share thru UDP socket interface starts here*/
				if(a[0]==5)
				{
					struct sockaddr_in recv_addr;
					socklen_t clilen=sizeof(struct sockaddr_in);
					char sendbuf[23];
					memset(sendbuf,0,sizeof(sendbuf));

					unsigned short myid=htons((nrot * 256) +1);
					bzero(recbuf,1500);
					rv = recvfrom(newsockfd1, recbuf, sizeof(recbuf), 0, (struct sockaddr *)&recv_addr, &clilen);
					if (rv > 0)
					{


						char *type = (char*) (recbuf + sizeof(struct iphdr));

						if(*type == 0x52)/*circuit extend*/
						{

							struct mycntrlmsg *msg = (struct mycntrlmsg*) (recbuf + sizeof(struct iphdr)+1);
							incmid=msg->circid;
							if(newid==0)
							{

								back_addr=recv_addr;/*back_addr used later in relay reply*/
								fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x%04x\n",ntohs(recv_addr.sin_port),(rv-20),*type,msg->circid,msg->portnum);
								fprintf(rouf2,"new extend circuit: incoming: 0x%02x, outgoing: 0x%02x at %d\n",ntohs(msg->circid),myid,ntohs(msg->portnum));
								fflush(rouf2);
								newid=msg->circid;
								nexthop=msg->portnum;
								struct in_addr addr;
								struct iphdr *ipn = (struct iphdr*) sendbuf;
								inet_pton(AF_INET, "127.0.0.1", &addr);
								ipn->daddr=addr.s_addr;
								ipn->saddr=addr.s_addr;
								ipn->protocol=253;
								char *typen= (char*) (sendbuf + sizeof(struct iphdr));
								*typen=0x53;/*cicuit extend done messge type*/
								struct mycntrlmsgr *msgn = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
								msgn->circid=msg->circid;
								if (sendto(newsockfd1, sendbuf, sizeof(sendbuf), 0, (struct sockaddr *)&recv_addr, clilen) < 0) {
									perror("sendto failed");
									exit(0);
								}


							}
							else
							{
								fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x%04x\n",ntohs(recv_addr.sin_port),(rv-20),*type,msg->circid,msg->portnum);
								fprintf(rouf2,"forwarding extend circuit: incoming: 0x%02x, outgoing: 0x%02x at %d\n",ntohs(msg->circid),myid,ntohs(nexthop));
								fflush(rouf2);
								sender_addr.sin_family = AF_INET;
								sender_addr.sin_addr.s_addr = htonl(INADDR_ANY);
								sender_addr.sin_port=nexthop;
								msg->circid=myid;
								if (sendto(newsockfd1, recbuf, rv, 0, (struct sockaddr *)&sender_addr, clilen) < 0) {
									perror("sendto failed");
									exit(0);
								}
								rv = recvfrom(newsockfd1, recbuf, sizeof(recbuf), 0, NULL, NULL);
								if (rv > 0)
								{
									//struct iphdr *ip = (struct iphdr*) recbuf;
									type = (char*) (recbuf + sizeof(struct iphdr));
									struct mycntrlmsgr *msgn = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
									fprintf(rouf2,"pkt from port: %d, length: %d, contents: 0x%02x%04x\n",ntohs(sender_addr.sin_port),(rv-20),*type,msgn->circid);
									fflush(rouf2);
									msgn->circid=incmid;
									fprintf(rouf2,"forwarding extend-done circuit, incoming: 0x%02x, outgoing: 0x%02x at %d\n",ntohs(myid),ntohs(incmid),ntohs(recv_addr.sin_port));
									fflush(rouf2);
									if (sendto(newsockfd1, recbuf, rv, 0, (struct sockaddr *)&recv_addr, clilen) < 0) {
										perror("sendto failed");
										exit(0);
									}

								}

							}
						}/*relay data*/
						else if(*type == 0x51)
						{
							struct iphdr *ip1 = (struct iphdr*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							soaddr.s_addr=ip1->saddr;/*for storing source ip so that it can be used later for dst*/
							if (nexthop == 0xffff)
							{
								struct iphdr *ip = (struct iphdr*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
								struct icmphdr *icmp = (struct icmphdr*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr)+ sizeof(struct iphdr));
								struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
								unsigned char *contents = (unsigned char *) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
								fprintf(rouf2, "pkt from port: %d, length: %d, contents:0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*type,msgr->circid);
								fflush(rouf2);
								int i=0;
								for(i=0;i<(rv-23);i++)
								{
									//fprintf(rouf2,"%x",temp[i]);
									fprintf(rouf2,"%x",*contents);contents++;
									fflush(rouf2);
								}
								fprintf(rouf2,"\n");
								fflush(rouf2);
								out_addr.sin_family = AF_INET;
								out_addr.sin_addr.s_addr = ip->daddr;
								char tempo1[INET_ADDRSTRLEN];
								char tempo2[INET_ADDRSTRLEN];
								struct in_addr soaddri;
								soaddri.s_addr = ip->saddr;

								inet_ntop(AF_INET, &(out_addr.sin_addr), tempo1, INET_ADDRSTRLEN);
								inet_ntop(AF_INET, &(soaddri), tempo2, INET_ADDRSTRLEN);
								fprintf(rouf2,"outgoing packet, circuit incoming: 0x%02x, incoming src:%s, outgoing src: %s, dst: %s\n",ntohs(msgr->circid),tempo2,ipadd,tempo1);
								fflush(rouf2);

								/*checking if the packet is to be forwarded or is meant for the router itself*/
								if(strncmp(tempo1,"10.5.51",7)==0)
								{
									printf("sigthu bidu guru\n");
									soaddri.s_addr = ip->saddr;
									ip->saddr=ip->daddr;
									ip->daddr=soaddri.s_addr;
									icmp->type=0;
									icmp->checksum=0;
									/*checksum calculation*/
									int len=rv-20;
									u_short *icm=((u_short *)recbuf+ sizeof(struct iphdr));
									int check=in_cksum(icm,len);
									icmp->checksum = check;

									if (sendto(newsockfd1, recbuf, rv, 0, (struct sockaddr *)&back_addr, sizeof(gserv_addr)) < 0)
									{
										perror("sendto failed");
										exit(0);
									}

								}
								else
								{
									struct iovec iov[1];/*reference :http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html*/
									iov[0].iov_base=icmp;
									iov[0].iov_len=rv-43;

									struct msghdr message;
									message.msg_name=&out_addr;
									message.msg_namelen=sizeof(out_addr);
									message.msg_control=0;
									message.msg_controllen=0;
									message.msg_iov=iov;
									message.msg_iovlen=1;
									if (sendmsg(rawfd,&message,0)==-1) {
										perror("error at sendmsg \n");
										exit(0);
									}
								}
							}
							else
							{
								struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
								unsigned char *contents = (unsigned char *) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
								fprintf(rouf2, "pkt from port: %d, length: %d, contents:0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*type,msgr->circid);
								fflush(rouf2);
								int i=0;
								for(i=0;i<(rv-23);i++)
								{
									fprintf(rouf2,"%x",*contents);contents++;
									fflush(rouf2);
								}
								fprintf(rouf2,"\n");
								fflush(rouf2);
								struct in_addr soaddr,dsaddr;
								char tempo1[INET_ADDRSTRLEN];
								char tempo2[INET_ADDRSTRLEN];
								sender_addr.sin_family = AF_INET;
								sender_addr.sin_addr.s_addr = htonl(INADDR_ANY);
								sender_addr.sin_port=nexthop;
								struct iphdr *ip = (struct iphdr*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
								soaddr.s_addr=ip->saddr;
								inet_ntop(AF_INET, &(soaddr), tempo1, INET_ADDRSTRLEN);
								dsaddr.s_addr=ip->daddr;
								inet_ntop(AF_INET, &(dsaddr), tempo2, INET_ADDRSTRLEN);
								fprintf(rouf2,"relay packet, circuit incoming: 0x%02x, outgoing: 0x%02x, incoming src:%s, outgoing src: %s, dst: %s \n",ntohs(msgr->circid),ntohs(myid),tempo1,ipadd,tempo2);
								fflush(rouf2);
								inet_pton(AF_INET, ipadd, &(soaddr));
								ip->saddr=soaddr.s_addr;
								msgr->circid=myid;
								if (sendto(newsockfd1, recbuf, rv, 0, (struct sockaddr *)&sender_addr, clilen) < 0) {
									perror("sendto failed");
									exit(0);
								}
							}

						}
						else if(*type == 0x54)/*relay return data*/
						{
							struct iphdr *ip = (struct iphdr*) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (recbuf + sizeof(struct iphdr)+1);
							unsigned char *contents = (unsigned char *) (recbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							fprintf(rouf2, "pkt from port: %d, length: %d, contents:0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*type,msgr->circid);
							fflush(rouf2);
							int i=0;
							for(i=0;i<(rv-23);i++)
							{
								fprintf(rouf2,"%x",*contents);contents++;
								fflush(rouf2);
							}
							fprintf(rouf2,"\n");
							fflush(rouf2);
							ip->daddr=soaddr.s_addr;
							msgr->circid=incmid;
							char tempo1[INET_ADDRSTRLEN];
							char tempo2[INET_ADDRSTRLEN];
							struct in_addr soaddrt,dsaddrt;
							soaddrt.s_addr=ip->saddr;
							inet_ntop(AF_INET, &(soaddrt), tempo1, INET_ADDRSTRLEN);
							dsaddrt.s_addr=ip->daddr;
							inet_ntop(AF_INET, &(dsaddrt), tempo2, INET_ADDRSTRLEN);
							fprintf(rouf2,"relay reply packet, circuit incoming: 0x%02x, outgoing: 0x%02x, src: %s, incoming dst: %s, outgoing dest: %s\n",ntohs(myid),ntohs(incmid),tempo1,ipadd,tempo2);
							fflush(rouf2);
							if (sendto(newsockfd1, recbuf, rv, 0, (struct sockaddr *)&back_addr, clilen) < 0) {
								perror("sendto failed");
								exit(0);
							}

						}

					}
				}

				/*stage 5 code for messages shared through UDP socket interface ends here*/







				/*stage 4 code for messages shared through UDP  socket interface starts here*/

				if(a[0]<=4)
				{
					rv = recvfrom(newsockfd1, recbuf, sizeof(recbuf), 0, NULL, NULL);
					if (rv > 0)
					{

						struct iphdr *ip = (struct iphdr*) recbuf;
						struct icmphdr *icmp = (struct icmphdr*) (recbuf+ sizeof(struct iphdr));
						out_addr.sin_family = AF_INET;
						out_addr.sin_addr.s_addr = ip->daddr;
						char tempo1[INET_ADDRSTRLEN];
						char tempo2[INET_ADDRSTRLEN];
						soaddr.s_addr = ip->saddr;

						inet_ntop(AF_INET, &(out_addr.sin_addr), tempo1, INET_ADDRSTRLEN);
						inet_ntop(AF_INET, &(soaddr), tempo2, INET_ADDRSTRLEN);
						fprintf(rouf2,"ICMP from port: %d, src: %s, dst: %s, type: %d\n",ntohs(gserv_addr.sin_port),tempo2,tempo1,icmp->type);
						fflush(rouf2);
						/*checking if the packet is to be forwarded or is meant for the router itself*/
						if(strncmp(tempo1,"10.5.51",7)==0)
						{
							printf("sigthu bidu guru\n");
							soaddr.s_addr = ip->saddr;
							ip->saddr=ip->daddr;
							ip->daddr=soaddr.s_addr;
							icmp->type=0;
							icmp->checksum=0;
							int len=rv-20;
							u_short *icm=((u_short *)recbuf+ sizeof(struct iphdr));
							int check=in_cksum(icm,len);
							icmp->checksum = check;
							if (sendto(newsockfd1, recbuf, rv, 0, (struct sockaddr *)&gserv_addr, sizeof(gserv_addr)) < 0)
							{
								perror("sendto failed");
								exit(0);
							}

						}
						else
						{

							struct iovec iov[1];/*reference :http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html*/
							iov[0].iov_base=icmp;
							iov[0].iov_len=rv-20;

							struct msghdr message;
							message.msg_name=&out_addr;
							message.msg_namelen=sizeof(out_addr);
							message.msg_control=0;
							message.msg_controllen=0;
							message.msg_iov=iov;
							message.msg_iovlen=1;
							if (sendmsg(rawfd,&message,0)==-1)
							{
								perror("error at sendmsg \n");
								exit(0);
							}
						}
					}
				}

				/*stage 4 code for messages shared through UDP socket interface ends here*/






			}/*packets coming from raw socket meant for ICMP*/
			if(FD_ISSET(rawfd,&readfds))
			{
				pktsent=0;
				/*common code for raw socket interface starts here*/
				struct iovec iov[1];
				iov[0].iov_base=icmppkt;
				iov[0].iov_len=sizeof(icmppkt);

				/*struct msghdr message;*/
				struct msghdr message;
				message.msg_name=&sender_addr;
				message.msg_namelen=sizeof(sender_addr);
				message.msg_control=0;
				message.msg_controllen=0;
				message.msg_iov=iov;
				message.msg_iovlen=1;
				if ((rvm=recvmsg(rawfd, &message, 0)) < 0)
				{
					printf("error at recvmsg \n");
					exit(0);
				}




				struct iphdr *ip1 = (struct iphdr*) icmppkt;
				struct icmphdr *icmp1 = (struct icmphdr*)(icmppkt + sizeof(struct iphdr));
				struct in_addr soaddr1= {ip1->saddr};
				struct in_addr dsaddr1= {ip1->daddr};
				char tempo1[INET_ADDRSTRLEN];
				char tempo2[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(soaddr1), tempo1, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(soaddr), tempo2, INET_ADDRSTRLEN);

				ip1->daddr=soaddr.s_addr;
				ip1->check=0;
				u_short *icm=(u_short *)icmppkt;
				int check=in_cksum(icm,20);
				ip1->check= check;


				/*common code for raw socket interface starts here*/





				/*stage 4 code for messages shared through raw socket interface starts here*/


				if(a[0]<=4)
				{
					fprintf(rouf2,"ICMP from raw sock, src: %s, dst: %s, type: %d \n",tempo1,tempo2,icmp1->type);
					fflush(rouf2);
					if (sendto(newsockfd1, icmppkt, rvm, 0, (struct sockaddr *)&gserv_addr, sizeof(gserv_addr)) < 0)
					{
						perror("sendto failed");
						exit(0);
					}
				}

				/*stage 4 code for messages shared through raw socket interface ends  here*/





				/*stage 5 code for messages shared through raw socket interface starts here*/
				else if(a[0]==5)
				{
					char sendbuf[rvm+23];
					char *pts;
					char *ptr=icmppkt;
					memset(sendbuf,0,sizeof(sendbuf));
					struct in_addr addr;
					struct iphdr *ip = (struct iphdr*) sendbuf;
					fprintf(rouf2,"incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x\n",tempo1,tempo2,ntohs(incmid));
					fflush(rouf2);
					inet_pton(AF_INET, "127.0.0.1", &addr);
					ip->daddr=addr.s_addr;
					ip->saddr=addr.s_addr;
					ip->protocol=253;
					char *type= (char*) (sendbuf + sizeof(struct iphdr));
					*type=0x54;
					struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
					msgr->circid=incmid;
					pts=(char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					int cnt=0;
					while(cnt<rvm)
					{
						*pts=*ptr;
						pts++;ptr++;
						cnt++;
					}
					if (sendto(newsockfd1, sendbuf, sizeof(sendbuf), 0, (struct sockaddr *)&back_addr, sizeof(back_addr)) < 0) {
							perror("sendto failed");
							exit(0);
					}
				}

				/*stage 5 code for messages shared through raw socket interface ends here*/
				else if(a[0]==6 || a[0]==7 || a[0]==9)
				{
					unsigned char *crypt_text;
					int crypt_text_len;
					unsigned char *clear_crypt_text;
					int clear_crypt_text_len;
					//unsigned char key_data[16];

					AES_KEY enc_key;
					AES_KEY dec_key;

					inet_ntop(AF_INET, &(dsaddr1), tempo2, INET_ADDRSTRLEN);
					char sendbuf[1000];
					unsigned char *pts;
					char *ptr=icmppkt;
					memset(sendbuf,0,sizeof(sendbuf));
					struct in_addr addr;
					struct iphdr *ip = (struct iphdr*) sendbuf;
			/*inmcid prob here*/	fprintf(rouf2,"incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x\n",tempo1,tempo2,incmid);
					fflush(rouf2);
					inet_pton(AF_INET, "127.0.0.1", &addr);
					ip->daddr=addr.s_addr;
					ip->saddr=addr.s_addr;
					ip->protocol=253;
					char *type= (char*) (sendbuf + sizeof(struct iphdr));
					*type=0x64;
					struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
					msgr->circid=incmid;
					pts=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					int cnt=0;
					while(cnt<rvm)
					{
						*pts=*ptr;
						pts++;ptr++;
						cnt++;
					}
					struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					struct in_addr adddr;
					inet_pton(AF_INET, "0.0.0.0", &adddr);
					ipk->daddr=adddr.s_addr;
					pts=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					class_AES_set_encrypt_key(myyykey, &enc_key);
					class_AES_encrypt_with_padding(pts,rvm, &crypt_text, &crypt_text_len, &enc_key);
					int j=0;
					while(j<crypt_text_len)
					{
						sendbuf[j+23]=*crypt_text;
						j++;crypt_text++;
					}
					class_AES_set_decrypt_key(myyykey, &dec_key);
					class_AES_decrypt_with_padding(sendbuf+23, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);

					ip = (struct iphdr*)clear_crypt_text;
					if (sendto(newsockfd1, sendbuf, 23+crypt_text_len, 0, (struct sockaddr *)&pvaddr, sizeof(back_addr)) < 0) {
							perror("sendto failed");
							exit(0);
					}

				}

				else if(a[0]==8)
				{
					struct incmlist *current=listtt;
					int whichtupple=0;
					/*checking which tupple the incoming packet belongs to*/
					while(current != NULL)
					{

						struct iphdr *ip = (struct iphdr*) icmppkt;
						if(ip->saddr == current->intupple.src_addr)
						{
							if(ip->daddr == current->intupple.dest_addr)
							{
								if(ip->protocol == current->intupple.protocol)
								{
									if(ip->protocol == 1)
									{
										whichtupple=current->intupple.keyref;
										//different =0;
										break;
									}
									else
									{
										struct tcphdr *tcp = (struct tcphdr*) (icmppkt + sizeof(struct iphdr));
										if(tcp->source == current->intupple.src_port)
										{
											if(tcp->dest == current->intupple.dest_port)
											{
												whichtupple=current->intupple.keyref;
												//different =0;
												break;
											}
										}
									}
								}
							}
						}

						current = current->next;
						//currentkey=currentkey->nextky;
					}
					if(current == NULL)
					{
						printf("there was an errrorrrr");
						exit(0);
					}




					unsigned char *crypt_text;
					int crypt_text_len;
					unsigned char *clear_crypt_text;
					int clear_crypt_text_len;
					//unsigned char key_data[16];

					AES_KEY enc_key;
					AES_KEY dec_key;

					inet_ntop(AF_INET, &(dsaddr1), tempo2, INET_ADDRSTRLEN);

					unsigned char tempo[17];
					memset(tempo,'\0',sizeof(tempo));
					strncpy((char*)tempo,(char*)myyykey8[whichtupple],16);
					char sendbuf[1000];
					unsigned char *pts;
					char *ptr=icmppkt;
					memset(sendbuf,0,sizeof(sendbuf));
					struct in_addr addr;
					struct iphdr *ip = (struct iphdr*) sendbuf;
					fprintf(rouf2,"incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x\n",tempo1,tempo2,current->intupple.incm);
					fflush(rouf2);
					inet_pton(AF_INET, "127.0.0.1", &addr);
					ip->daddr=addr.s_addr;
					ip->saddr=addr.s_addr;
					ip->protocol=253;
					char *type= (char*) (sendbuf + sizeof(struct iphdr));
					*type=0x64;
					struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
					msgr->circid=current->intupple.incm;
					pts=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					int cnt=0;
					while(cnt<rvm)
					{
						*pts=*ptr;
						pts++;ptr++;
						cnt++;
					}
					struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					struct in_addr adddr;
					inet_pton(AF_INET, "0.0.0.0", &adddr);
					ipk->daddr=adddr.s_addr;
					pts=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					class_AES_set_encrypt_key(tempo, &enc_key);
					class_AES_encrypt_with_padding(pts,rvm, &crypt_text, &crypt_text_len, &enc_key);
					int j=0;
					while(j<crypt_text_len)
					{
						sendbuf[j+23]=*crypt_text;
						j++;crypt_text++;
					}
					class_AES_set_decrypt_key(tempo, &dec_key);
					class_AES_decrypt_with_padding(sendbuf+23, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);

					ip = (struct iphdr*)clear_crypt_text;
					if (sendto(newsockfd1, sendbuf, 23+crypt_text_len, 0, (struct sockaddr *)&(current->intupple.pv_addr), sizeof(back_addr)) < 0) {
							perror("sendto failed");
							exit(0);
					}

				}

			}/*packets coming from raw soxket meant for TCP*/
			if(FD_ISSET(rawtcpfd,&readfds))
			{
				pktsent=0;

				if(a[0]==7 || a[0]==9)
				{
				struct iovec iov[1];
				iov[0].iov_base=icmppkt;
				iov[0].iov_len=sizeof(icmppkt);

				/*struct msghdr message;*/
				struct msghdr message;
				message.msg_name=&sender_addr;
				message.msg_namelen=sizeof(sender_addr);
				message.msg_control=0;
				message.msg_controllen=0;
				message.msg_iov=iov;
				message.msg_iovlen=1;
				if ((rvm=recvmsg(rawtcpfd, &message, 0)) < 0)
				{
					printf("error at recvmsg \n");
					exit(0);
				}
				struct iphdr *ip1 = (struct iphdr*) icmppkt;
				struct in_addr soaddr1= {ip1->saddr};
				struct in_addr dsaddr1= {ip1->daddr};
				char tempo1[INET_ADDRSTRLEN];
				char tempo2[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(soaddr1), tempo1, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(dsaddr1), tempo2, INET_ADDRSTRLEN);

				unsigned char *crypt_text;
				int crypt_text_len;


				AES_KEY enc_key;
				//AES_KEY dec_key;


				char sendbuf[1000];
				unsigned char *pts;
				char *ptr=icmppkt;
				memset(sendbuf,0,sizeof(sendbuf));
				struct in_addr addr;
				struct iphdr *ip = (struct iphdr*) sendbuf;
				struct tcphdr *tcp=(struct tcphdr*)(icmppkt + sizeof(struct iphdr));
			/*incmid prob here*/fprintf(rouf2,"incoming TCP packet, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %lu, ackno: %lu, outgoing circuit: 0x%02x\n",tempo1,ntohs(tcp->source),tempo2,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack),ntohs(inocmid));
				fflush(rouf2);

				inet_pton(AF_INET, "127.0.0.1", &addr);
				ip->daddr=addr.s_addr;
				ip->saddr=addr.s_addr;
				ip->protocol=253;
				char *type= (char*) (sendbuf + sizeof(struct iphdr));
				*type=0x64;
				struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
				msgr->circid=inocmid;
				pts=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				int cnt=0;
				while(cnt<rvm)
				{
					*pts=*ptr;
					pts++;ptr++;
					cnt++;
				}
				struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				struct in_addr adddr;
				inet_pton(AF_INET, "0.0.0.0", &adddr);
				ipk->daddr=adddr.s_addr;
				pts=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
				class_AES_set_encrypt_key(myyykey, &enc_key);
				class_AES_encrypt_with_padding(pts,rvm, &crypt_text, &crypt_text_len, &enc_key);
				int j=0;
				while(j<crypt_text_len)
				{
					sendbuf[j+23]=*crypt_text;
					j++;crypt_text++;
				}
				if (sendto(newsockfd1, sendbuf, 23+crypt_text_len, 0, (struct sockaddr *)&pvaddr, sizeof(back_addr)) < 0) {
						perror("sendto failed");
						exit(0);
				}

				}


				else if(a[0]==8)
				{

					struct iovec iov[1];
					iov[0].iov_base=icmppkt;
					iov[0].iov_len=sizeof(icmppkt);

					/*struct msghdr message;*/
					struct msghdr message;
					message.msg_name=&sender_addr;
					message.msg_namelen=sizeof(sender_addr);
					message.msg_control=0;
					message.msg_controllen=0;
					message.msg_iov=iov;
					message.msg_iovlen=1;
					if ((rvm=recvmsg(rawtcpfd, &message, 0)) < 0)
					{
						printf("error at recvmsg \n");
						exit(0);
					}
					struct iphdr *ip1 = (struct iphdr*) icmppkt;
					struct tcphdr *tcp = (struct tcphdr*) (icmppkt + sizeof(struct iphdr));
					struct in_addr soaddr1= {ip1->saddr};
					struct in_addr dsaddr1= {ip1->daddr};
					char tempo1[INET_ADDRSTRLEN];
					char tempo2[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &(soaddr1), tempo1, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(dsaddr1), tempo2, INET_ADDRSTRLEN);


					struct incmlist *curtem=listtt;
					while(curtem !=NULL)
					{
						char tempo2[INET_ADDRSTRLEN];
						struct in_addr soaddri;
						soaddri.s_addr = curtem->intupple.src_addr;
						inet_ntop(AF_INET, &(soaddri), tempo2, INET_ADDRSTRLEN);
						curtem=curtem->next;
					}

					struct incmlist *current=listtt;
					int whichtupple=0;
					while(current != NULL)
					{

						struct iphdr *ip = (struct iphdr*) icmppkt;
						if(ip->saddr == current->intupple.src_addr)
						{
							if(ip->daddr == current->intupple.dest_addr)
							{
								if(ip->protocol == current->intupple.protocol)
								{
									if(ip->protocol == 1)
									{
										whichtupple=current->intupple.keyref;
										//different =0;
										break;
									}
									else
									{
										struct tcphdr *tcp = (struct tcphdr*) (icmppkt + sizeof(struct iphdr));
										if(tcp->source == current->intupple.src_port)
										{
											if(tcp->dest == current->intupple.dest_port)
											{
												//different =0;
												whichtupple=current->intupple.keyref;
												break;
											}
										}
									}
								}
							}
						}

						current = current->next;
						//currentkey=currentkey->nextky;
					}
					if(current == NULL)
					{
						printf("there was an errrorrrr");
						exit(0);
					}




					unsigned char *crypt_text;
					int crypt_text_len;
					unsigned char *clear_crypt_text;
					int clear_crypt_text_len;
					//unsigned char key_data[16];

					AES_KEY enc_key;
					AES_KEY dec_key;

					inet_ntop(AF_INET, &(dsaddr1), tempo2, INET_ADDRSTRLEN);


					unsigned char tempo[17];
					memset(tempo,'\0',sizeof(tempo));
					strncpy((char*)tempo,(char*)myyykey8[whichtupple],16);


					char sendbuf[1000];
					unsigned char *pts;
					char *ptr=icmppkt;
					memset(sendbuf,0,sizeof(sendbuf));
					struct in_addr addr;
					struct iphdr *ip = (struct iphdr*) sendbuf;
					fprintf(rouf2,"incoming TCP packet, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %lu, ackno: %lu, outgoing circuit: 0x%02x\n",tempo1,ntohs(tcp->source),tempo2,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack),ntohs(current->intupple.incm));
					fflush(rouf2);
					inet_pton(AF_INET, "127.0.0.1", &addr);
					ip->daddr=addr.s_addr;
					ip->saddr=addr.s_addr;
					ip->protocol=253;
					char *type= (char*) (sendbuf + sizeof(struct iphdr));
					*type=0x64;
					struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
				/*>>>*/	msgr->circid=current->intupple.incm;
					pts=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					int cnt=0;
					while(cnt<rvm)
					{
						*pts=*ptr;
						pts++;ptr++;
						cnt++;
					}
					struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
					struct in_addr adddr;
					inet_pton(AF_INET, "0.0.0.0", &adddr);
					ipk->daddr=adddr.s_addr;
					pts=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));


					class_AES_set_encrypt_key(tempo, &enc_key);
					class_AES_encrypt_with_padding(pts,rvm, &crypt_text, &crypt_text_len, &enc_key);
					int j=0;
					while(j<crypt_text_len)
					{
						sendbuf[j+23]=*crypt_text;
						j++;crypt_text++;
					}



					class_AES_set_decrypt_key(tempo, &dec_key);
					class_AES_decrypt_with_padding(sendbuf+23, crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);

					ip = (struct iphdr*)clear_crypt_text;
					if (sendto(newsockfd1, sendbuf, 23+crypt_text_len, 0, (struct sockaddr *)&(current->intupple.pv_addr), sizeof(back_addr)) < 0) {
							perror("sendto failed");
							exit(0);
					}

				}/*end of stage 8 condn*/


			}/*end of rawtcpfd condn*/

		}/*end of else for select function*/

	}/*end of while(1)*/
	fclose(rouf2);
	close(newsockfd1);
		exit(0);
}

