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

int gport=0;
//int tcpfd;
struct sockaddr_in gserv_addr;

/*void error(const char *msg)
{
    perror(msg);
    exit(0);

}*/


void sig_handler(int signo)
{
  if (signo == SIGINT)
    printf("received SIGINT\n");
	exit(0);
}



void SigCatcher(int n)
{
wait3(NULL,WNOHANG,NULL);
}
int main(int argc, char *argv[])
{
     int sockfd, portno;
    /* char buffer[256];*/
     struct sockaddr_in serv_addr,recv_addr;
     int n=0,pid;
    socklen_t clilen=sizeof(struct sockaddr_in);
    int fsthop=0;int fsthops[10];
    char **keys;int secrout=0,pktcount=0;
    unsigned short circuit=0x01;

	if (signal(SIGINT, sig_handler) == SIG_ERR)
  printf("\ncan't catch SIGINT\n");

	FILE *conf=NULL;
	char buf[1026];
	int a[4];
	int cnt=0;
	memset(buf, '\0', sizeof(buf));
	char *start_ptr,*tab_ptr,*tempstrn;
	conf = fopen(argv[1], "r");
		if (conf == NULL) 
		{
			fprintf(stderr, "Error in opening %s: %s for reading.\n",argv[2], strerror(errno));
			exit(0);
		}
	while(fgets(buf, sizeof(buf), conf) != NULL) 
	{
		if (buf[0] == '#')
		{
		continue;
		}
		if(buf[0]== ' ' || buf[0] == '\t' || buf[0]=='\n')
		{
			printf("Invamlid file format:empty line found\n");
			exit(0);
		}
		start_ptr=buf;
		tab_ptr = strchr(start_ptr, ' ');
		start_ptr = tab_ptr++;
		tempstrn= strrchr(start_ptr,'\n');
		*tempstrn='\0';
		a[cnt]=atoi(start_ptr);
		printf(" %d %s \n",a[cnt],start_ptr);
		cnt++;
	}
		int nrot=a[1];
		if(nrot==0 || nrot >6)
		{
			printf("Number of routers is invalid \n");
			exit(0);
		}
		struct sockaddr_in cli_addr[nrot];
		printf(">>>>>>>killl afterr %d\n",a[3]);

     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    /* if (sockfd < 0) 
        error("ERROR opening socket");*/
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
     serv_addr.sin_port = 0;
     bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
     socklen_t slen = sizeof(serv_addr);
     getsockname(sockfd, (struct sockaddr *)&serv_addr, &slen);
     portno = ntohs(serv_addr.sin_port);
     gserv_addr=serv_addr;
     printf("Proxy port number= %d\n",portno);/*prit this in the log file*/
     
	signal(SIGCHLD,SigCatcher);/*check where to insert this*/

     printf("%d \n",a[1]);
     char ipadd[14];
     memset(ipadd,'\0',sizeof(ipadd));

    FILE *prof1;
	char *mode = "w";
	char fil[20];
	 sprintf(fil,"stage%d.proxy.out",a[0]);
	prof1 = fopen(fil,mode);
	fprintf(prof1,"proxy port: %d\n",ntohs(serv_addr.sin_port));
	fflush(prof1);
     for(n=0;n<nrot;n++)
	{
		pid=fork();
		/* if (pid < 0)
            		 error("ERROR on fork");*/
        	 if (pid == 0)
		  {		close(sockfd);




		  /*char ipad[100];
		      char buf[100];
		       FILE *fp;
		       memset(ipad,'\0',sizeof(ipad));
		       memset(buf,'\0',sizeof(buf));

		       sprintf(buf,"/sbin/ifconfig eth%d |grep 'inet '|cut -d ' ' -f 10-11|awk '{ print $1 }'",n+1);
		       fp=popen(buf,"r");
		       if (fp == NULL) {
		               printf("Failed to run command\n" );
		               exit(0);
		       }

		       fgets(ipad, sizeof(ipad), fp);

		       ipad[strlen(ipad)-1]='\0';
		       printf("ip is %s\n",ipad);*/



		  	  	sprintf(ipadd,"192.168.20%d.2",(n+1));
		  		routerroutine(a,n+1,gserv_addr,ipadd);
        	  } 
		else /*the proxy(parent) should wait here to get a message from the child*/
		{	
			sprintf(ipadd,"192.168.20%d.2",(n+1));
			printf("proxy port from proxy %d \n", ntohs(serv_addr.sin_port));
			char buffer[256];
			bzero(buffer,256);
			  
			   int rv = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&cli_addr[n], &clilen);/*stage one :waiting for router "im up message"*/
				if (rv > 0)
				{
				printf("received message: %s\n", buffer);

				printf("router port from proxy %d \n", ntohs(cli_addr[n].sin_port));
				}
				fprintf(prof1,"router: %d, pid: %d, port: %d ",(n+1),pid,ntohs(cli_addr[n].sin_port));
				fflush(prof1);
				if(a[0]>=5)
				{
					fprintf(prof1,"IP: %s\n",ipadd);
                	fflush(prof1);
				}
				else
				{
					fprintf(prof1,"\n");
                	fflush(prof1);
				}
				if(n<(nrot-1))
				{

					continue;
				}
				/*CIRCUIT CREATION for stage5 Starts*/
				if(a[0]==5)
				{
					int nhops=a[2];
				fsthop=creatckt_s5(sockfd, nrot,nhops, cli_addr,prof1);
				}/*CIRCUIT CREATION for stage5 Ends*/

				/*CIRCUIT CREATION for stage6 Starts*/
				if(a[0]==6 || a[0]==7 || a[0]==9)
				{
					int nhops=a[2];int i=0;int j=0;
					keys = malloc(nhops * sizeof(char*));
					for (i=0; i < nhops; i++)
					    keys[i] = malloc((17) * sizeof(char));
					fsthop=creatckt_s6(sockfd, nrot,nhops, cli_addr,prof1,keys,&secrout);
					//printf("here here \n");
					//printf("%d selected router key is %c\n",j+1,keys[j][j]);
					for(j=0;j < nhops;j++)
					    {
						//printf("here here \n");
						printf("%d selected router key is %s\n",j+1,keys[j]);
					    }

				}/*CIRCUIT CREATION for stage6 Ends*/
				printf(">>>>>>>>>>>>>the second router is %d\n",secrout);

				char tun_name[IFNAMSIZ];
				fd_set readfds;
			  /* Connect to the device */
				  strcpy(tun_name,"tun1");
				  int tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);  /* tun interface */
				  int maxfd = tun_fd > sockfd ? tun_fd:sockfd;
				  maxfd++;
				  if(tun_fd < 0){
					perror("Allocating interface");
					exit(1);
				  }
				  char buffert[2000];
				  bzero(buffert,2000);
				  struct in_addr sourceaddr;
				  struct tuplist *list;
				  list = malloc(sizeof(struct tuplist));
				  list->fitupple.protocol=0;
				  list->next=NULL;
				  struct keylist *klis;
				  klis = malloc(sizeof(struct keylist));
				  //klis->keys[0]=NULL;
				  klis->nextky=NULL;
				  struct tuplist *current;
				  struct keylist *currentkey;
              while(1)
			  {	
				FD_ZERO(&readfds);
				FD_SET(sockfd, &readfds);
				FD_SET(tun_fd, &readfds);
				if (select(maxfd , &readfds, NULL, NULL,NULL ) == -1){
				perror("select error");
				}
				if( FD_ISSET(sockfd,&readfds))
				{
					 rv = recvfrom(sockfd, buffert, sizeof(buffert), 0, (struct sockaddr *)&recv_addr, &clilen);
                                         if (rv > 0)
         	                         {
                                        if(a[0]<=4)
                                        {
										struct iphdr *ip = (struct iphdr*) buffert;
										struct icmphdr *icmp = (struct icmphdr*) (buffert + sizeof(struct iphdr));
										char str[INET_ADDRSTRLEN];
										struct in_addr soaddr = {ip->saddr};
										struct in_addr dsaddr = {ip->daddr};
										inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);
										printf("PROXY recvd from router:Read %d bytes from rt port %d : src %s dst %s and type is %d\n", rv, ntohs(recv_addr.sin_port),inet_ntoa(soaddr),str,icmp->type);
										if(a[0]>1)
										fprintf(prof1,"ICMP from port: %d src: %s, dst: %s, type: %d\n",ntohs(recv_addr.sin_port),inet_ntoa(soaddr),str,icmp->type);
										fflush(prof1);
										write(tun_fd,buffert,rv);

                                        }
                                        else if(a[0]==5)
                                        {
                                        	//struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (buffert + sizeof(struct iphdr)+1);
                                        	char *type = (char*) (buffert + sizeof(struct iphdr));
                                        	struct iphdr *ip = (struct iphdr*) (buffert + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
                                        	struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (buffert + sizeof(struct iphdr)+1);
                                        	unsigned char *contents = (unsigned char *) (buffert + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
                        					struct in_addr soaddr1= {ip->saddr};
                        					struct in_addr dsaddr1= {ip->daddr};
                        					char tempo1[INET_ADDRSTRLEN];
                        					char tempo2[INET_ADDRSTRLEN];
                        					inet_ntop(AF_INET, &(soaddr1), tempo1, INET_ADDRSTRLEN);
                        					inet_ntop(AF_INET, &(dsaddr1), tempo2, INET_ADDRSTRLEN);
    										fprintf(prof1,"pkt from port: %d, length: %d, contents:0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*type,msgr->circid);
    										fflush(prof1);
    										int i;
    										for(i=0;i<(rv-23);i++)
    										{
    											//fprintf(rouf2,"%x",temp[i]);
    											fprintf(prof1,"%x",*contents);contents++;
    											fflush(prof1);
    										}
    										fprintf(prof1,"\n");
    										fflush(prof1);
    										fprintf(prof1,"incoming packet, circuit incoming: 0x01, src: %s, dst: %s\n",tempo1,tempo2);
    										fflush(prof1);
                							char icmppkt[1500];
                							memset(icmppkt,0,sizeof(icmppkt));
                							int j=0;
                							for(i=23;i<rv;i++)
                							{
                								icmppkt[j]=buffert[i];
                								j++;
                							}

                							ip = (struct iphdr*) icmppkt;
                							ip->check=0;
                							u_short *icm=(u_short *)icmppkt;
                							int check=in_cksum(icm,20);
                							ip->check= check;
                							printf("%d\n",rv);
                							write(tun_fd,icmppkt,rv-23);

                                        }
                                        else if(a[0]==6)
                                        {
                    						unsigned char *clear_crypt_text;
                    						int clear_crypt_text_len;
                    						//AES_KEY enc_key;
                    						AES_KEY dec_key;
                                        	printf("finally here at proxy to decrypt:msg len to decrypt is %d\n ",rv-23);
                                        	char *type = (char*) (buffert + sizeof(struct iphdr));
                                        	struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (buffert + sizeof(struct iphdr)+1);
                                        	unsigned char *contents = (unsigned char *) (buffert + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
    										fprintf(prof1,"pkt from port: %d, length: %d, contents:0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*type,msgr->circid);
    										fflush(prof1);
    										int i;
    										for(i=0;i<(rv-23);i++)
    										{
    											//fprintf(rouf2,"%x",temp[i]);
    											fprintf(prof1,"%x",*contents);contents++;
    											fflush(prof1);
    										}
    										fprintf(prof1,"\n");
    										fflush(prof1);

                                        	unsigned char keybuffer[1000];int cont;/*int i=0;*/
                                        	unsigned char *dec=(unsigned char*) (buffert + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
											for(cont=0;cont<rv-23;cont++)
											{
												keybuffer[cont]=*dec;
												dec++;

											}
											int aclen=rv-23;
											for(i=0;i<=a[2]-1;i++)
											{	printf("key[%d] is %s \n",i,keys[i]);
												class_AES_set_decrypt_key(keys[i], &dec_key);
												class_AES_decrypt_with_padding(keybuffer, aclen, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
												memset(keybuffer,'\0',sizeof(keybuffer));
												//strncpy((char*)keybuffer,(char*)crypt_text,crypt_text_len);
												int co=0;
												for(co=0;co<clear_crypt_text_len;co++)
												{
													keybuffer[co]=*clear_crypt_text;
													clear_crypt_text++;

												}
												aclen=clear_crypt_text_len;
											}
											printf("Final length after decryption is %d \n",clear_crypt_text_len);
                							struct iphdr *ip = (struct iphdr*)keybuffer;

                							char str[INET_ADDRSTRLEN];
                							char str1[INET_ADDRSTRLEN];
                							struct in_addr soaddr = {ip->saddr};
                							struct in_addr dsaddr = {ip->daddr};
                							inet_ntop(AF_INET, &(soaddr), str1, INET_ADDRSTRLEN);
                							printf("source is %s \n",str1);

                							ip->daddr=sourceaddr.s_addr;
                							ip->check=0;
                							u_short *icm=(u_short *)keybuffer;
                							int check=in_cksum(icm,20);
                							ip->check= check;
                							dsaddr.s_addr = ip->daddr;
                							inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);
                							printf("dst is %s \n",str);
    										fprintf(prof1,"incoming packet, circuit incoming: 0x01, src: %s, dst: %s\n",str1,str);
    										fflush(prof1);
                							write(tun_fd,keybuffer,clear_crypt_text_len);

                                        }
                    					else if(a[0]==7 || a[0]==9)
                    					{
                    						/*if(rv=3)
                    						{
        										fprintf(prof1,"Router2 is down\n");
        										fflush(prof1);
                    						}*/

                       						unsigned char *clear_crypt_text;
                        						int clear_crypt_text_len;
                        						//AES_KEY enc_key;
                        						AES_KEY dec_key;
                                            	printf("finally here at proxy to decrypt:msg len to decrypt is %d\n ",rv-23);
                                            	char *type = (char*) (buffert + sizeof(struct iphdr));
                                            	struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (buffert + sizeof(struct iphdr)+1);
                                            	unsigned char *contents = (unsigned char *) (buffert + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
        										fprintf(prof1,"pkt from port: %d, length: %d, contents:0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*type,msgr->circid);
        										fflush(prof1);
        										int i;
        										for(i=0;i<(rv-23);i++)
        										{
        											//fprintf(rouf2,"%x",temp[i]);
        											fprintf(prof1,"%x",*contents);contents++;
        											fflush(prof1);
        										}
        										fprintf(prof1,"\n");
        										fflush(prof1);

                                            	unsigned char keybuffer[1000];int cont;/*int i=0;*/
                                            	unsigned char *dec=(unsigned char*) (buffert + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
    											for(cont=0;cont<rv-23;cont++)
    											{
    												keybuffer[cont]=*dec;
    												dec++;

    											}
    											int aclen=rv-23;
    											for(i=0;i<=a[2]-1;i++)
    											{	printf("key[%d] is %s \n",i,keys[i]);
    												class_AES_set_decrypt_key(keys[i], &dec_key);
    												class_AES_decrypt_with_padding(keybuffer, aclen, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
    												memset(keybuffer,'\0',sizeof(keybuffer));
    												//strncpy((char*)keybuffer,(char*)crypt_text,crypt_text_len);
    												int co=0;
    												for(co=0;co<clear_crypt_text_len;co++)
    												{
    													keybuffer[co]=*clear_crypt_text;
    													clear_crypt_text++;

    												}
    												aclen=clear_crypt_text_len;
    											}
    											printf("Final length after decryption is %d \n",clear_crypt_text_len);
                    							struct iphdr *ip = (struct iphdr*)keybuffer;

                    							if(ip->protocol == IPPROTO_TCP)
                    							{
                    							struct tcphdr *tcp=(struct tcphdr*)(keybuffer+sizeof(struct iphdr));
                    							char str[INET_ADDRSTRLEN];
                    							char str1[INET_ADDRSTRLEN];
                    							struct in_addr soaddr = {ip->saddr};
                    							struct in_addr dsaddr = {ip->daddr};
                    							inet_ntop(AF_INET, &(soaddr), str1, INET_ADDRSTRLEN);
                    							printf("source is %s \n",str1);

                    							ip->daddr=sourceaddr.s_addr;
                    							ip->check=0;
                    							u_short *icm=(u_short *)keybuffer;
                    							int check=in_cksum(icm,20);
                    							ip->check= check;
                    							dsaddr.s_addr = ip->daddr;
                    							inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);
                    							printf("dst is %s \n",str);
        										fprintf(prof1,"incoming TCP packet, circuit incoming: 0x01, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %ld, ackno: %ld\n",str1,ntohs(tcp->source),str,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack));
        										fflush(prof1);
        										struct tcp_pseudo pseudo;
        										pseudo.dest_addr=ip->daddr;
        										pseudo.src_addr=ip->saddr;
        										pseudo.reserved=0;
        										pseudo.protocol=IPPROTO_TCP;
        										pseudo.tcplen=htons(clear_crypt_text_len-20);
        										tcp->check=0;
        										char *chksmbuf;
        										int csize = sizeof(struct tcp_pseudo) + clear_crypt_text_len-20;
        										chksmbuf = malloc(csize);
        										memcpy(chksmbuf , (char*) &pseudo , sizeof (struct tcp_pseudo));
        										memcpy(chksmbuf + sizeof(struct tcp_pseudo) , tcp , clear_crypt_text_len-20);
        								    	u_short *tcpchk=((u_short *)chksmbuf);
        								    	int checkt=in_cksum(tcpchk,csize);

        										tcp->check=checkt;
                    							}
                    							else
                    							{
                        							char str[INET_ADDRSTRLEN];
                        							char str1[INET_ADDRSTRLEN];
                        							struct in_addr soaddr = {ip->saddr};
                        							struct in_addr dsaddr = {ip->daddr};
                        							inet_ntop(AF_INET, &(soaddr), str1, INET_ADDRSTRLEN);
                        							printf("source is %s \n",str1);

                        							ip->daddr=sourceaddr.s_addr;
                        							ip->check=0;
                        							u_short *icm=(u_short *)keybuffer;
                        							int check=in_cksum(icm,20);
                        							ip->check= check;
                        							dsaddr.s_addr = ip->daddr;
                        							inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);
                        							printf("dst is %s \n",str);
            										fprintf(prof1,"incoming packet, circuit incoming: 0x01, src: %s, dst: %s\n",str1,str);
            										fflush(prof1);
                    							}
                    							write(tun_fd,keybuffer,clear_crypt_text_len);
                                        }






                                        else if(a[0]==8)
                                        {
                                        	printf("Entered proxy to send back to tunnel in stage 8 \n");
                                			struct mycntrlmsgr *msgk = (struct mycntrlmsgr*) (buffert + sizeof(struct iphdr)+1);
                                			int dif=ntohs(msgk->circid)-circuit;
                                			int p=0;printf("diff is %d\n", dif);
                                			currentkey=klis;
                                			for(p=0;p<dif;p++)
                                			{
                                				currentkey=currentkey->nextky;
                                			}
                                			if(currentkey==NULL)
                                			{
                                				printf("at end of proxy: no key enddd");
                                				exit(0);
                                			}

                       						unsigned char *clear_crypt_text;
                        						int clear_crypt_text_len;
                        						//AES_KEY enc_key;
                        						AES_KEY dec_key;
                                            	printf("finally here at proxy to decrypt:msg len to decrypt is %d\n ",rv-23);
                                            	char *type = (char*) (buffert + sizeof(struct iphdr));
                                            	struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (buffert + sizeof(struct iphdr)+1);
                                            	unsigned char *contents = (unsigned char *) (buffert + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
        										fprintf(prof1,"pkt from port: %d, length: %d, contents:0x%02x%04x",ntohs(recv_addr.sin_port),(rv-20),*type,msgr->circid);
        										fflush(prof1);
        										int i;
        										for(i=0;i<(rv-23);i++)
        										{
        											//fprintf(rouf2,"%x",temp[i]);
        											fprintf(prof1,"%x",*contents);contents++;
        											fflush(prof1);
        										}
        										fprintf(prof1,"\n");
        										fflush(prof1);

                                            	unsigned char keybuffer[1000];int cont;/*int i=0;*/
                                            	unsigned char *dec=(unsigned char*) (buffert + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
    											for(cont=0;cont<rv-23;cont++)
    											{
    												keybuffer[cont]=*dec;
    												dec++;

    											}
    											int aclen=rv-23;
    											for(i=0;i<=a[2]-1;i++)
    											{	printf("key[%d] is %s \n",i,currentkey->keys[i]);
    												class_AES_set_decrypt_key(currentkey->keys[i], &dec_key);
    												class_AES_decrypt_with_padding(keybuffer, aclen, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
    												memset(keybuffer,'\0',sizeof(keybuffer));
    												//strncpy((char*)keybuffer,(char*)crypt_text,crypt_text_len);
    												int co=0;
    												for(co=0;co<clear_crypt_text_len;co++)
    												{
    													keybuffer[co]=*clear_crypt_text;
    													clear_crypt_text++;

    												}
    												aclen=clear_crypt_text_len;
    											}
    											printf("Final length after decryption is %d \n",clear_crypt_text_len);
                    							struct iphdr *ip = (struct iphdr*)keybuffer;

                    							if(ip->protocol == IPPROTO_TCP)
                    							{
                    							struct tcphdr *tcp=(struct tcphdr*)(keybuffer+sizeof(struct iphdr));
                    							char str[INET_ADDRSTRLEN];
                    							char str1[INET_ADDRSTRLEN];
                    							struct in_addr soaddr = {ip->saddr};
                    							struct in_addr dsaddr = {ip->daddr};
                    							inet_ntop(AF_INET, &(soaddr), str1, INET_ADDRSTRLEN);
                    							printf("source is %s \n",str1);

                    							ip->daddr=sourceaddr.s_addr;
                    							ip->check=0;
                    							u_short *icm=(u_short *)keybuffer;
                    							int check=in_cksum(icm,20);
                    							ip->check= check;
                    							dsaddr.s_addr = ip->daddr;
                    							inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);
                    							printf("dst is %s \n",str);
        										fprintf(prof1,"incoming TCP packet, circuit incoming: 0x%02x, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %lu, ackno: %lu\n",ntohs(msgk->circid),str1,ntohs(tcp->source),str,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack));
        										fflush(prof1);

        										struct tcp_pseudo pseudo;
        										pseudo.dest_addr=ip->daddr;
        										pseudo.src_addr=ip->saddr;
        										pseudo.reserved=0;
        										pseudo.protocol=IPPROTO_TCP;
        										pseudo.tcplen=htons(clear_crypt_text_len-20);
        										tcp->check=0;
        										char *chksmbuf;
        										int csize = sizeof(struct tcp_pseudo) + clear_crypt_text_len-20;
        										chksmbuf = malloc(csize);
        										memcpy(chksmbuf , (char*) &pseudo , sizeof (struct tcp_pseudo));
        										memcpy(chksmbuf + sizeof(struct tcp_pseudo) , tcp , clear_crypt_text_len-20);
        								    	u_short *tcpchk=((u_short *)chksmbuf);
        								    	int checkt=in_cksum(tcpchk,csize);

        										tcp->check=checkt;
                    							}
                    							else
                    							{
                        							char str[INET_ADDRSTRLEN];
                        							char str1[INET_ADDRSTRLEN];
                        							struct in_addr soaddr = {ip->saddr};
                        							struct in_addr dsaddr = {ip->daddr};
                        							inet_ntop(AF_INET, &(soaddr), str1, INET_ADDRSTRLEN);
                        							printf("source is %s \n",str1);

                        							ip->daddr=sourceaddr.s_addr;
                        							ip->check=0;
                        							u_short *icm=(u_short *)keybuffer;
                        							int check=in_cksum(icm,20);
                        							ip->check= check;
                        							dsaddr.s_addr = ip->daddr;
                        							inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);
                        							printf("dst is %s \n",str);
            										fprintf(prof1,"incoming packet, circuit incoming: 0x%02x, src: %s, dst: %s\n",ntohs(msgk->circid),str1,str);
            										fflush(prof1);
                    							}



                    							write(tun_fd,keybuffer,clear_crypt_text_len);



                                        }









			       		 }
				}
	   			if(FD_ISSET(tun_fd,&readfds))
				{
						int nread = read(tun_fd,buffert,sizeof(buffert));
						    if(nread < 0) {
					      perror("Reading from interface");
					      close(tun_fd);
					      exit(1);
					    }




					if(a[0]==8)/*fucked up stage :@:@:@:@*/
					{	int whichtupple=0;

						if(list->fitupple.protocol == 0)
						{
							struct iphdr *ip = (struct iphdr*) buffert;
							list->fitupple.src_addr=ip->saddr;
							list->fitupple.dest_addr=ip->daddr;
							list->fitupple.protocol=ip->protocol;
							if(ip->protocol == 1)
							{
								list->fitupple.dest_port=0;
								list->fitupple.src_port=0;
							}
							else
							{
								struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
								list->fitupple.dest_port=tcp->dest;
								list->fitupple.src_port=tcp->source;
							}
							int nhops=a[2];int i=0;int j=0;
							keys = malloc(nhops * sizeof(char*));
							for (i=0; i < nhops; i++)
							    keys[i] = malloc((17) * sizeof(char));
							fsthops[0]=creatckt_s8(sockfd, nrot,nhops, cli_addr,prof1,keys);
							for(j=0;j < nhops;j++)
							    {
								//printf("here here \n");
								printf("%d selected router key is %s\n",j+1,keys[j]);
								strncpy(klis->keys[j],keys[j],17);
							    }
							current=list;
							currentkey=klis;
							whichtupple=0;

							if(ip->protocol==6)
							{
								struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
								struct in_addr soaddr = {ip->saddr};
								struct in_addr dsaddr = {ip->daddr};
								char strs[INET_ADDRSTRLEN];
								char strd[INET_ADDRSTRLEN];
								inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
								inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);

								fprintf(prof1,"TCP from tunnel, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %lu, ackno: %lu\n",strs,ntohs(tcp->source),strd,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack));
								fflush(prof1);
							}
							if(ip->protocol==1)
							{
								struct icmphdr *icmp = (struct icmphdr*) (buffert + sizeof(struct iphdr));
								struct in_addr soaddr = {ip->saddr};
								struct in_addr dsaddr = {ip->daddr};
								char strs[INET_ADDRSTRLEN];
								char strd[INET_ADDRSTRLEN];
								inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
								inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);
									fprintf(prof1,"ICMP from tunnel: src: %s, dst: %s, type: %d\n",strs,strd,icmp->type);
									fflush(prof1);
							}




								//struct iphdr *ip = (struct iphdr*) buffert;
							   //struct icmphdr *icmp = (struct icmphdr*) (buffert + sizeof(struct iphdr));
							   //struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
								char str[INET_ADDRSTRLEN];
								struct in_addr soaddr = {ip->saddr};
								struct in_addr dsaddr = {ip->daddr};
								inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);


							unsigned char *crypt_text;
							int crypt_text_len;
							//unsigned char *clear_crypt_text;
							//int clear_crypt_text_len;
							AES_KEY enc_key;
							//AES_KEY dec_key;

							char sendbuf[1500];
							char *pts;
							char *ptr=buffert;
							memset(sendbuf,0,sizeof(sendbuf));
							struct in_addr addr;
							ip = (struct iphdr*) sendbuf;
							inet_pton(AF_INET, "127.0.0.1", &addr);
							ip->daddr=addr.s_addr;
							ip->saddr=addr.s_addr;
							ip->protocol=253;
							//tcpfd=tcp->source;
							char *type= (char*) (sendbuf + sizeof(struct iphdr));
							*type=0x61;
							struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
							msgr->circid=htons(circuit);
							pts=(char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							int cnt=0;
							while(cnt<nread)
							{
								*pts=*ptr;
								pts++;ptr++;
								cnt++;
							}
							struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							sourceaddr.s_addr=ipk->saddr;/*use later to send it to ping*/
							char strs[INET_ADDRSTRLEN];
							char strd[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);


							/*tcpfd= socket(AF_INET, SOCK_RAW,IPPROTO_TCP);
							if (tcpfd==-1) {
								perror("socket creation failed");
								exit(0);
							}
							struct sockaddr_in rawtcp_addr;
							rawtcp_addr.sin_family = AF_INET;
							printf("just abo to check this shit %s \n",ipadd);
							inet_pton(AF_INET, ipadd, &(rawtcp_addr.sin_addr));
							rawtcp_addr.sin_port = tcp->source;
							bind(tcpfd,(struct sockaddr *)&rawtcp_addr, sizeof(rawtcp_addr));*/



							inet_pton(AF_INET, "0.0.0.0", &addr);
							ipk->saddr=addr.s_addr;
							unsigned char *enc=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							i=0;int aclen=nread;
							unsigned char keybuffer[1000];int cont;
							for(cont=0;cont<nread;cont++)
							{
								keybuffer[cont]=*enc;
								enc++;

							}
							for(i=a[2]-1;i>=0;i--)
							{
								class_AES_set_encrypt_key(currentkey->keys[i], &enc_key);
								class_AES_encrypt_with_padding(keybuffer, aclen, &crypt_text, &crypt_text_len, &enc_key);
								memset(keybuffer,'\0',sizeof(keybuffer));
								//strncpy((char*)keybuffer,(char*)crypt_text,crypt_text_len);
								int co=0;
								for(co=0;co<crypt_text_len;co++)
								{
									keybuffer[co]=*crypt_text;
									crypt_text++;

								}
								aclen=crypt_text_len;
								//class_AES_set_decrypt_key(keys[i], &dec_key);
								//printf("key hodoskonde : crypttext len is %d and strlen is %d\n",crypt_text_len,strlen((char*)keybuffer));
								//class_AES_decrypt_with_padding(keybuffer,crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
								//printf("Enc/dec:ENC key is %s, len is %d\n",keybuffer,crypt_text_len );
								//printf("Enc/dec:DEC key is %s, len is %d\n",clear_crypt_text,clear_crypt_text_len );
							}
							//free(crypt_text);
							//free(clear_crypt_text);
							int co=0;
							printf("entering the loop \n");
							while(co<crypt_text_len)
							{
								sendbuf[co+23]=keybuffer[co];
								co++;
							}
							printf("sending for first packet\n");
							if (sendto(sockfd, sendbuf,23+crypt_text_len, 0, (struct sockaddr *)&cli_addr[fsthops[0]], clilen) < 0) {
								perror("sendto failed");
								return 0;
							}







							/*sendto here with encryption*/




						}
						else
						{	int different = 1;
							current=list;currentkey=klis;
							while(current != NULL)
							{

								struct iphdr *ip = (struct iphdr*) buffert;
								if(ip->saddr == current->fitupple.src_addr)
								{
									if(ip->daddr == current->fitupple.dest_addr)
									{
										if(ip->protocol == current->fitupple.protocol)
										{
											if(ip->protocol == 1)
											{
												different =0;
												break;
											}
											else
											{
												struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
												if(tcp->source == current->fitupple.src_port)
												{
													if(tcp->dest == current->fitupple.dest_port)
													{
														different =0;
														break;
													}
												}
											}
										}
									}
								}
								whichtupple++;
								current = current->next;
								currentkey=currentkey->nextky;
							}

							if(different == 0)
							{
								/*make the relay packet and then encrytpion using keys pointed by whichtupple and then sendto using fsthops[whichtupple]
								 * make current=list and currentkey=klis*/



								struct iphdr *ip = (struct iphdr*) buffert;
							   //struct icmphdr *icmp = (struct icmphdr*) (buffert + sizeof(struct iphdr));
							   //struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
								char str[INET_ADDRSTRLEN];
								//struct in_addr soaddr = {ip->saddr};
								struct in_addr dsaddr = {ip->daddr};
								inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);


								if(ip->protocol==6)
								{
									struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
									struct in_addr soaddr = {ip->saddr};
									struct in_addr dsaddr = {ip->daddr};
									char strs[INET_ADDRSTRLEN];
									char strd[INET_ADDRSTRLEN];
									inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
									inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);

									fprintf(prof1,"TCP from tunnel, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %lu, ackno: %lu\n",strs,ntohs(tcp->source),strd,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack));
									fflush(prof1);
								}
								if(ip->protocol==1)
								{
									struct icmphdr *icmp = (struct icmphdr*) (buffert + sizeof(struct iphdr));
									struct in_addr soaddr = {ip->saddr};
									struct in_addr dsaddr = {ip->daddr};
									char strs[INET_ADDRSTRLEN];
									char strd[INET_ADDRSTRLEN];
									inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
									inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);
										fprintf(prof1,"ICMP from tunnel: src: %s, dst: %s, type: %d\n",strs,strd,icmp->type);
										fflush(prof1);
								}



							unsigned char *crypt_text;
							int crypt_text_len;
							unsigned char *clear_crypt_text;
							int clear_crypt_text_len;
							AES_KEY enc_key;
							AES_KEY dec_key;

							char sendbuf[1500];
							char *pts;
							char *ptr=buffert;
							memset(sendbuf,0,sizeof(sendbuf));
							struct in_addr addr;
							ip = (struct iphdr*) sendbuf;
							inet_pton(AF_INET, "127.0.0.1", &addr);
							ip->daddr=addr.s_addr;
							ip->saddr=addr.s_addr;
							ip->protocol=253;
							//tcpfd=tcp->source;
							char *type= (char*) (sendbuf + sizeof(struct iphdr));
							*type=0x61;
							struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
							msgr->circid=htons(circuit+whichtupple);
							pts=(char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							int cnt=0;
							while(cnt<nread)
							{
								*pts=*ptr;
								pts++;ptr++;
								cnt++;
							}
							struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							sourceaddr.s_addr=ipk->saddr;/*use later to send it to ping*/
							//char strs[INET_ADDRSTRLEN];
							//char strd[INET_ADDRSTRLEN];
							//inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
							//inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);
							//fprintf(prof1,"TCP from tunnel, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %d, ackno: %d\n",strs,tcp->source,strd,tcp->dest,ntohl(tcp->seq),ntohl(tcp->ack));
							//fflush(prof1);

							/*tcpfd= socket(AF_INET, SOCK_RAW,IPPROTO_TCP);
							if (tcpfd==-1) {
								perror("socket creation failed");
								exit(0);
							}
							struct sockaddr_in rawtcp_addr;
							rawtcp_addr.sin_family = AF_INET;
							printf("just abo to check this shit %s \n",ipadd);
							inet_pton(AF_INET, ipadd, &(rawtcp_addr.sin_addr));
							rawtcp_addr.sin_port = tcp->source;
							bind(tcpfd,(struct sockaddr *)&rawtcp_addr, sizeof(rawtcp_addr));*/



							inet_pton(AF_INET, "0.0.0.0", &addr);
							ipk->saddr=addr.s_addr;
							unsigned char *enc=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							int i=0;int aclen=nread;
							unsigned char keybuffer[1000];int cont;
							for(cont=0;cont<nread;cont++)
							{
								keybuffer[cont]=*enc;
								enc++;

							}
							for(i=a[2]-1;i>=0;i--)
							{
								class_AES_set_encrypt_key(currentkey->keys[i], &enc_key);
								class_AES_encrypt_with_padding(keybuffer, aclen, &crypt_text, &crypt_text_len, &enc_key);
								memset(keybuffer,'\0',sizeof(keybuffer));
								//strncpy((char*)keybuffer,(char*)crypt_text,crypt_text_len);
								int co=0;
								for(co=0;co<crypt_text_len;co++)
								{
									keybuffer[co]=*crypt_text;
									crypt_text++;

								}
								aclen=crypt_text_len;
								class_AES_set_decrypt_key(currentkey->keys[i], &dec_key);
								printf("key hodoskonde : crypttext len is %d and strlen is %d\n",crypt_text_len,strlen((char*)keybuffer));
								class_AES_decrypt_with_padding(keybuffer,crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
								printf("Enc/dec:ENC key is %s, len is %d\n",keybuffer,crypt_text_len );
								printf("Enc/dec:DEC key is %s, len is %d\n",clear_crypt_text,clear_crypt_text_len );
							}
							//free(crypt_text);
							//free(clear_crypt_text);
							int co=0;
							printf("entering the loop \n");
							while(co<crypt_text_len)
							{
								sendbuf[co+23]=keybuffer[co];
								co++;
							}
							printf("sending in different =0 \n");
							if (sendto(sockfd, sendbuf,23+crypt_text_len, 0, (struct sockaddr *)&cli_addr[fsthops[whichtupple]], clilen) < 0) {
								perror("sendto failed");
								return 0;
							}

							current=list;currentkey=klis;












							}
							else if(different == 1)
							{
								//current=malloc(sizeof(struct tuplist));
								current=list;currentkey=klis;
								while(current->next != NULL)
								{
									current=current->next;
									currentkey=currentkey->nextky;
								}
								struct tuplist *newtup=(struct tuplist*)malloc(sizeof(struct tuplist));
												newtup->next=NULL;

								struct iphdr *ip = (struct iphdr*) buffert;
								newtup->fitupple.src_addr=ip->saddr;
								newtup->fitupple.dest_addr=ip->daddr;
								newtup->fitupple.protocol=ip->protocol;
								if(ip->protocol == 1)
								{
									newtup->fitupple.dest_port=0;
									newtup->fitupple.src_port=0;
								}
								else
								{
									struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
									newtup->fitupple.dest_port=tcp->dest;
									newtup->fitupple.src_port=tcp->source;
								}
								current->next=newtup;





								int nhops=a[2];int i=0;int j=0;
								keys = malloc(nhops * sizeof(char*));
								for (i=0; i < nhops; i++)
								    keys[i] = malloc((17) * sizeof(char));
								fsthops[whichtupple]=creatckt_s8(sockfd, nrot,nhops, cli_addr,prof1,keys);

								struct keylist *newkeys=(struct keylist*)malloc(sizeof(struct keylist));
								newkeys->nextky=NULL;
								/*if(currentkey == NULL)
								{
									printf("currentkey was indeed empty \n");
									currentkey=malloc(sizeof(struct keylist));

								}*/
								for(j=0;j < nhops;j++)
								    {
									//printf("here here \n");
									printf("%d selected router key is %s\n",j+1,keys[j]);
									strncpy(newkeys->keys[j],keys[j],17);
								    }

									currentkey->nextky=newkeys;

								/*make packet make the circuit ID = whichtupple>>> using this circuit ID you can store the keys in an array at the routers*/
								/*sendto here with encryption and set current=list and currentkey=klis*/

									if(ip->protocol==6)
									{
										struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
										struct in_addr soaddr = {ip->saddr};
										struct in_addr dsaddr = {ip->daddr};
										char strs[INET_ADDRSTRLEN];
										char strd[INET_ADDRSTRLEN];
										inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
										inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);

										fprintf(prof1,"TCP from tunnel, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %lu, ackno: %lu\n",strs,ntohs(tcp->source),strd,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack));
										fflush(prof1);
									}
									if(ip->protocol==1)
									{
										struct icmphdr *icmp = (struct icmphdr*) (buffert + sizeof(struct iphdr));
										struct in_addr soaddr = {ip->saddr};
										struct in_addr dsaddr = {ip->daddr};
										char strs[INET_ADDRSTRLEN];
										char strd[INET_ADDRSTRLEN];
										inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
										inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);
											fprintf(prof1,"ICMP from tunnel: src: %s, dst: %s, type: %d\n",strs,strd,icmp->type);
											fflush(prof1);
									}



								if(currentkey != NULL)
								{
									printf("currentkey was not empty now \n");
									printf("1st key is in current key is %s\n",currentkey->keys[0]);
									if(klis->nextky == NULL)
									{
										printf("What the fuck is wrong hereeeee\n");
									}

								}




								//struct iphdr *ip = (struct iphdr*) buffert;
							   //struct icmphdr *icmp = (struct icmphdr*) (buffert + sizeof(struct iphdr));
							   //struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
								char str[INET_ADDRSTRLEN];
								//struct in_addr soaddr = {ip->saddr};
								struct in_addr dsaddr = {ip->daddr};
								inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);


							unsigned char *crypt_text;
							int crypt_text_len;
							//unsigned char *clear_crypt_text;
							//int clear_crypt_text_len;
							AES_KEY enc_key;
							//AES_KEY dec_key;

							char sendbuf[1500];
							char *pts;
							char *ptr=buffert;
							memset(sendbuf,0,sizeof(sendbuf));
							struct in_addr addr;
							ip = (struct iphdr*) sendbuf;
							inet_pton(AF_INET, "127.0.0.1", &addr);
							ip->daddr=addr.s_addr;
							ip->saddr=addr.s_addr;
							ip->protocol=253;
							//tcpfd=tcp->source;
							char *type= (char*) (sendbuf + sizeof(struct iphdr));
							*type=0x61;
							struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
							msgr->circid=htons(circuit+whichtupple);
							pts=(char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							int cnt=0;
							while(cnt<nread)
							{
								*pts=*ptr;
								pts++;ptr++;
								cnt++;
							}
							struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							sourceaddr.s_addr=ipk->saddr;/*use later to send it to ping*/
							//char strs[INET_ADDRSTRLEN];
							//char strd[INET_ADDRSTRLEN];
							//inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
							//inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);
							//fprintf(prof1,"TCP from tunnel, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %d, ackno: %d\n",strs,tcp->source,strd,tcp->dest,ntohl(tcp->seq),ntohl(tcp->ack));
							//fflush(prof1);

							/*tcpfd= socket(AF_INET, SOCK_RAW,IPPROTO_TCP);
							if (tcpfd==-1) {
								perror("socket creation failed");
								exit(0);
							}
							struct sockaddr_in rawtcp_addr;
							rawtcp_addr.sin_family = AF_INET;
							printf("just abo to check this shit %s \n",ipadd);
							inet_pton(AF_INET, ipadd, &(rawtcp_addr.sin_addr));
							rawtcp_addr.sin_port = tcp->source;
							bind(tcpfd,(struct sockaddr *)&rawtcp_addr, sizeof(rawtcp_addr));*/



							inet_pton(AF_INET, "0.0.0.0", &addr);
							ipk->saddr=addr.s_addr;
							unsigned char *enc=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
							 i=0;int aclen=nread;
							unsigned char keybuffer[1000];int cont;
							for(cont=0;cont<nread;cont++)
							{
								keybuffer[cont]=*enc;
								enc++;

							}
							for(i=a[2]-1;i>=0;i--)
							{
								//if(current)
								printf("keys checking: %s \n",currentkey->nextky->keys[i]);
								class_AES_set_encrypt_key(currentkey->nextky->keys[i], &enc_key);
								class_AES_encrypt_with_padding(keybuffer, aclen, &crypt_text, &crypt_text_len, &enc_key);
								memset(keybuffer,'\0',sizeof(keybuffer));
								//strncpy((char*)keybuffer,(char*)crypt_text,crypt_text_len);
								int co=0;
								for(co=0;co<crypt_text_len;co++)
								{
									keybuffer[co]=*crypt_text;
									crypt_text++;

								}
								aclen=crypt_text_len;
								//class_AES_set_decrypt_key(keys[i], &dec_key);
								//printf("key hodoskonde : crypttext len is %d and strlen is %d\n",crypt_text_len,strlen((char*)keybuffer));
								//class_AES_decrypt_with_padding(keybuffer,crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
								//printf("Enc/dec:ENC key is %s, len is %d\n",keybuffer,crypt_text_len );
								//printf("Enc/dec:DEC key is %s, len is %d\n",clear_crypt_text,clear_crypt_text_len );
							}
							//free(crypt_text);
							//free(clear_crypt_text);
							int co=0;
							printf("entering the loop \n");
							while(co<crypt_text_len)
							{
								sendbuf[co+23]=keybuffer[co];
								co++;
							}
							printf("sending\n");
							if (sendto(sockfd, sendbuf,23+crypt_text_len, 0, (struct sockaddr *)&cli_addr[fsthops[whichtupple]], clilen) < 0) {
								perror("sendto failed");
								return 0;
							}

							current=list;currentkey=klis;







							}



						}

					}
					
					
					struct iphdr *ip = (struct iphdr*) buffert;
					   struct icmphdr *icmp = (struct icmphdr*) (buffert + sizeof(struct iphdr));
					   struct tcphdr *tcp = (struct tcphdr*) (buffert + sizeof(struct iphdr));
						char str[INET_ADDRSTRLEN];
						struct in_addr soaddr = {ip->saddr};
						struct in_addr dsaddr = {ip->daddr};
						inet_ntop(AF_INET, &(dsaddr), str, INET_ADDRSTRLEN);
					   printf("PROXYYYYYYY:Read %d bytes from device %s : src %s dst %s and type is %d\n", nread, tun_name,inet_ntoa(soaddr),str,icmp->type);
					if(a[0]>1 )
						if(ip->protocol==1 && a[0]!=8)
						{
					fprintf(prof1,"ICMP from tunnel: src: %s, dst: %s, type: %d\n",inet_ntoa(soaddr),str,icmp->type);
					fflush(prof1);
						}
					/*stage 4 code*/
					if(a[0]<=4)
					{
						int mod=(htonl(dsaddr.s_addr))%nrot;
						if (sendto(sockfd, buffert, nread, 0, (struct sockaddr *)&cli_addr[mod], clilen) < 0) {
						perror("sendto failed");
						return 0;
						}
					}/*stage 4 code ends and stage 5 and 6 starts*/
					else if(a[0]==5)
					{
						char sendbuf[nread+23];
						char *pts;
						char *ptr=buffert;
						memset(sendbuf,0,sizeof(sendbuf));
						struct in_addr addr;
						ip = (struct iphdr*) sendbuf;
						inet_pton(AF_INET, "127.0.0.1", &addr);
						ip->daddr=addr.s_addr;
						ip->saddr=addr.s_addr;
						ip->protocol=253;
						char *type= (char*) (sendbuf + sizeof(struct iphdr));
						*type=0x51;
						struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
						msgr->circid=htons(0x01);
						pts=(char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
						int cnt=0;
						while(cnt<nread)
						{
							*pts=*ptr;
							pts++;ptr++;
							cnt++;
						}

							if (sendto(sockfd, sendbuf, sizeof(sendbuf), 0, (struct sockaddr *)&cli_addr[fsthop], clilen) < 0) {
									perror("sendto failed");
									return 0;
							}




					}
					else if(a[0]==6)
					{
						printf("in stage 6 bro\n");
						unsigned char *crypt_text;
						int crypt_text_len;
						unsigned char *clear_crypt_text;
						int clear_crypt_text_len;
						AES_KEY enc_key;
						AES_KEY dec_key;

						char sendbuf[1500];
						char *pts;
						char *ptr=buffert;
						memset(sendbuf,0,sizeof(sendbuf));
						struct in_addr addr;
						ip = (struct iphdr*) sendbuf;
						inet_pton(AF_INET, "127.0.0.1", &addr);
						ip->daddr=addr.s_addr;
						ip->saddr=addr.s_addr;
						ip->protocol=253;
						char *type= (char*) (sendbuf + sizeof(struct iphdr));
						*type=0x61;
						struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
						msgr->circid=0x01;
						pts=(char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
						int cnt=0;
						while(cnt<nread)
						{
							*pts=*ptr;
							pts++;ptr++;
							cnt++;
						}
						struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
						sourceaddr.s_addr=ipk->saddr;/*use later to send it to ping*/
						inet_pton(AF_INET, "0.0.0.0", &addr);
						ipk->saddr=addr.s_addr;
						unsigned char *enc=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
						int i=0;int aclen=nread;
						unsigned char keybuffer[1000];int cont;
						for(cont=0;cont<nread;cont++)
						{
							keybuffer[cont]=*enc;
							enc++;

						}
						for(i=a[2]-1;i>=0;i--)
						{
							class_AES_set_encrypt_key(keys[i], &enc_key);
							class_AES_encrypt_with_padding(keybuffer, aclen, &crypt_text, &crypt_text_len, &enc_key);
							memset(keybuffer,'\0',sizeof(keybuffer));
							//strncpy((char*)keybuffer,(char*)crypt_text,crypt_text_len);
							int co=0;
							for(co=0;co<crypt_text_len;co++)
							{
								keybuffer[co]=*crypt_text;
								crypt_text++;

							}
							aclen=crypt_text_len;
							class_AES_set_decrypt_key(keys[i], &dec_key);
							printf("key hodoskonde : crypttext len is %d and strlen is %d\n",crypt_text_len,strlen((char*)keybuffer));
							class_AES_decrypt_with_padding(keybuffer,crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
							printf("Enc/dec:ENC key is %s, len is %d\n",keybuffer,crypt_text_len );
							printf("Enc/dec:DEC key is %s, len is %d\n",clear_crypt_text,clear_crypt_text_len );
						}
						//free(crypt_text);
						//free(clear_crypt_text);
						int co=0;
						printf("entering the loop \n");
						while(co<crypt_text_len)
						{
							sendbuf[co+23]=keybuffer[co];
							co++;
						}
						printf("sending\n");
						if (sendto(sockfd, sendbuf,23+crypt_text_len, 0, (struct sockaddr *)&cli_addr[fsthop], clilen) < 0) {
							perror("sendto failed");
							return 0;
						}


					}/*stage 7*/
					else if(a[0]==7 || a[0]==9)
					{

						char strs[INET_ADDRSTRLEN];
						char strd[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &(dsaddr), strd, INET_ADDRSTRLEN);
						inet_ntop(AF_INET, &(soaddr), strs, INET_ADDRSTRLEN);
						if(ip->protocol!=1)
						{
						fprintf(prof1,"TCP from tunnel, src IP/port: %s:%d, dst IP/port: %s:%d, seqno: %lu, ackno: %lu\n",strs,ntohs(tcp->source),strd,ntohs(tcp->dest),(long unsigned)ntohl(tcp->seq),(long unsigned)ntohl(tcp->ack));
						fflush(prof1);
						}
						printf("in stage 7 bro\n");
						unsigned char *crypt_text;
						int crypt_text_len;
						unsigned char *clear_crypt_text;
						int clear_crypt_text_len;
						AES_KEY enc_key;
						AES_KEY dec_key;

						char sendbuf[1500];
						char *pts;
						char *ptr=buffert;
						memset(sendbuf,0,sizeof(sendbuf));
						struct in_addr addr;
						ip = (struct iphdr*) sendbuf;
						inet_pton(AF_INET, "127.0.0.1", &addr);
						ip->daddr=addr.s_addr;
						ip->saddr=addr.s_addr;
						ip->protocol=253;
						//tcpfd=tcp->source;
						char *type= (char*) (sendbuf + sizeof(struct iphdr));
						*type=0x61;
						struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
						msgr->circid=0x01;
						pts=(char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
						int cnt=0;
						while(cnt<nread)
						{
							*pts=*ptr;
							pts++;ptr++;
							cnt++;
						}
						struct iphdr *ipk=(struct iphdr*)(sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
						sourceaddr.s_addr=ipk->saddr;/*use later to send it to ping*/



						/*tcpfd= socket(AF_INET, SOCK_RAW,IPPROTO_TCP);
						if (tcpfd==-1) {
							perror("socket creation failed");
							exit(0);
						}
						struct sockaddr_in rawtcp_addr;
						rawtcp_addr.sin_family = AF_INET;
						printf("just abo to check this shit %s \n",ipadd);
						inet_pton(AF_INET, ipadd, &(rawtcp_addr.sin_addr));
						rawtcp_addr.sin_port = tcp->source;
						bind(tcpfd,(struct sockaddr *)&rawtcp_addr, sizeof(rawtcp_addr));*/



						inet_pton(AF_INET, "0.0.0.0", &addr);
						ipk->saddr=addr.s_addr;
						unsigned char *enc=(unsigned char*) (sendbuf + sizeof(struct iphdr)+1+sizeof(struct mycntrlmsgr));
						int i=0;int aclen=nread;
						unsigned char keybuffer[1000];int cont;
						for(cont=0;cont<nread;cont++)
						{
							keybuffer[cont]=*enc;
							enc++;

						}
						for(i=a[2]-1;i>=0;i--)
						{
							class_AES_set_encrypt_key(keys[i], &enc_key);
							class_AES_encrypt_with_padding(keybuffer, aclen, &crypt_text, &crypt_text_len, &enc_key);
							memset(keybuffer,'\0',sizeof(keybuffer));
							//strncpy((char*)keybuffer,(char*)crypt_text,crypt_text_len);
							int co=0;
							for(co=0;co<crypt_text_len;co++)
							{
								keybuffer[co]=*crypt_text;
								crypt_text++;

							}
							aclen=crypt_text_len;
							class_AES_set_decrypt_key(keys[i], &dec_key);
							printf("key hodoskonde : crypttext len is %d and strlen is %d\n",crypt_text_len,strlen((char*)keybuffer));
							class_AES_decrypt_with_padding(keybuffer,crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
							printf("Enc/dec:ENC key is %s, len is %d\n",keybuffer,crypt_text_len );
							printf("Enc/dec:DEC key is %s, len is %d\n",clear_crypt_text,clear_crypt_text_len );
						}
						//free(crypt_text);
						//free(clear_crypt_text);
						int co=0;
						printf("entering the loop \n");
						while(co<crypt_text_len)
						{
							sendbuf[co+23]=keybuffer[co];
							co++;
						}
						printf("sending\n");
						if (sendto(sockfd, sendbuf,23+crypt_text_len, 0, (struct sockaddr *)&cli_addr[fsthop], clilen) < 0) {
							perror("sendto failed");
							return 0;
						}

						pktcount++;
						if(a[0]==9)
						{
							if(pktcount==a[3])
							{
								printf(">>>>>>>>>>>>>>>>>>>>>>>proxy has to kill now\n");
								printf("2nd router port number is %d \n",ntohs((cli_addr[secrout]).sin_port));
								char sendbuf[1500];
								memset(sendbuf,0,sizeof(sendbuf));
								struct in_addr addr;
								ip = (struct iphdr*) sendbuf;
								inet_pton(AF_INET, "127.0.0.1", &addr);
								ip->daddr=addr.s_addr;
								ip->saddr=addr.s_addr;
								ip->protocol=253;
								//tcpfd=tcp->source;
								unsigned char *type= (unsigned char*) (sendbuf + sizeof(struct iphdr));
								*type=0x91;
								struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (sendbuf + sizeof(struct iphdr)+1);
								msgr->circid=0x01;
								if (sendto(sockfd, sendbuf,23, 0, (struct sockaddr *)&cli_addr[secrout], clilen) < 0) {
									perror("sendto failed");
									return 0;
								}



							}
						}






					}/*end of stage 7*/

									
				}/*end of tunfd*/
			
		}
		fclose(prof1);	
		}
}
return 0;
}

