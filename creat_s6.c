#include "tunnel.h"

#define CUTT

int creatckt_s6(int sockfd,int nrot,int nhops,struct sockaddr_in cli_addr[],FILE *prof1,unsigned char *rrkeys[17],int *secrout)
{
	socklen_t clilen=sizeof(struct sockaddr_in);
	struct sockaddr_in recv_addr;
	int hopselk[nhops];char msgbufk[1500];unsigned char rkeys[nhops][17];
	int i=0,j=0;
	srand(time(NULL));
	for(i=0;i<nhops;i++)
	{
randomagain:hopselk[i]=rand() % nrot;
		if(i==0)
		{
			fprintf(prof1,"hop: %d, router: %d\n",i+1,hopselk[i]+1);
			fflush(prof1);
			continue;
		}
		for(j=i-1;j>=0;j--)
		{
			if(hopselk[i]==hopselk[j])
				goto randomagain;

		}
		fprintf(prof1,"hop: %d, router: %d\n",i+1,hopselk[i]+1);
		fflush(prof1);
	}

	*secrout=hopselk[1];

	/*key generating code */
	int kint[4];unsigned char proxkey[16];
	int k;
    for(k=0;k<4;k++)
    {
    		kint[k]=rand();
            printf("%x",kint[k]);
    }
    sprintf((char*)proxkey,"%08x%08x",kint[0],kint[1]);


	memset(rkeys,'\0',sizeof(rkeys));
    /*generating router keys*/

    for(i=0;i<nhops;i++)
    {
    	for(j=0;j<16;j++)
    	{
    		rkeys[i][j]=(proxkey[j])^(hopselk[i]+1);
    	}
    	strncpy((char*)rrkeys[i],(char*)rkeys[i],17);
    }

	for(i=0;i<nhops;i++)
		{

	/*key sending code:making our own custom packet*/


		unsigned char *crypt_text;
		int crypt_text_len;
		unsigned char *clear_crypt_text;
		int clear_crypt_text_len;

		AES_KEY enc_key;
		AES_KEY dec_key;


		memset(msgbufk,0,sizeof(msgbufk));
		struct in_addr addrk;
		struct iphdr *ipk = (struct iphdr*) msgbufk;
		inet_pton(AF_INET, "127.0.0.1", &addrk);
		ipk->daddr=addrk.s_addr;
		ipk->saddr=addrk.s_addr;
		ipk->protocol=253;
		char *typek= (char*) (msgbufk + sizeof(struct iphdr));
		*typek=0x65;
		struct mycntrlmsgr *msgk = (struct mycntrlmsgr*) (msgbufk + sizeof(struct iphdr)+1);
		msgk->circid=htons(0x01);
		int j=0;
		unsigned char keybuffer[1000];
		memset(keybuffer,'\0',sizeof(keybuffer));
		if(i!=0)/*if i is not equal to 0 then encryption has to be done with keys of routers that are alreasy made*/
		{	int count;
			strncpy((char*)keybuffer,(char*)rkeys[i],16);

			int aclen=strlen((char*)keybuffer);

			for(count=i-1;count>=0;count--)
			{
				class_AES_set_encrypt_key(rkeys[count], &enc_key);
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
				class_AES_set_decrypt_key(rkeys[count], &dec_key);
				class_AES_decrypt_with_padding(keybuffer,crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);

			}
			j=0;
			while(j<crypt_text_len)
			{
				msgbufk[j+23]=keybuffer[j];
				j++;
			}
			j=0;
		}
		else/*for first router no encryption, jus sending the keys*/
		{
			crypt_text_len=16;
			while(j<16)
			{
				msgbufk[j+23]=rkeys[i][j];
				j++;
			}
		}
		fprintf(prof1,"new-fake-diffe-hellman, router index: %d, circuit outgoing: 0x01, key: 0x",hopselk[i]+1);
		fflush(prof1);
		j=0;
		while(j<16)
		{
			fprintf(prof1,"%02x",rkeys[i][j]);
			fflush(prof1);
			j++;
		}
		fprintf(prof1,"\n");
		if (sendto(sockfd, msgbufk,23+crypt_text_len, 0, (struct sockaddr *)&cli_addr[hopselk[0]], clilen) < 0) {
			perror("sendto failed");
			return 0;
		}
		char temp[100];
		int rvm = recvfrom(sockfd,temp , sizeof(temp), 0, (struct sockaddr *)&recv_addr, &clilen);
		if (rvm > 0)
		{
			/*just checking the return after delivering the keys*/
		}

		int portnum;
		if(i<(nhops-1))
		{
			portnum=(cli_addr[hopselk[i+1]].sin_port);
		}
		else
			portnum=0xffff;

		unsigned char portbuffer[1000];
		memset(portbuffer,'\0',sizeof(portbuffer));
		sprintf((char*)portbuffer,"%d",portnum);
		int cnt;int aclen= strlen((char*)portbuffer);
		for(cnt=i;cnt>=0;cnt--)
		{
			class_AES_set_encrypt_key(rkeys[cnt], &enc_key);
			class_AES_encrypt_with_padding(portbuffer,aclen, &crypt_text, &crypt_text_len, &enc_key);
			memset(portbuffer,'\0',sizeof(portbuffer));
			int co=0;
			for(co=0;co<crypt_text_len;co++)
			{
				portbuffer[co]=*crypt_text;
				crypt_text++;

			}
			aclen=crypt_text_len;
			class_AES_set_decrypt_key(rkeys[cnt], &dec_key);
			class_AES_decrypt_with_padding(portbuffer,crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &dec_key);
		}
		/*making encrypted-circuit-extend packet*/
		memset(msgbufk,'\0',sizeof(msgbufk));
		ipk = (struct iphdr*) msgbufk;
		inet_pton(AF_INET, "127.0.0.1", &addrk);
		ipk->daddr=addrk.s_addr;
		ipk->saddr=addrk.s_addr;
		ipk->protocol=253;
		typek= (char*) (msgbufk + sizeof(struct iphdr));
		*typek=0x62;
		msgk = (struct mycntrlmsgr*) (msgbufk + sizeof(struct iphdr)+1);
		msgk->circid=htons(0x01);j=0;
		printf("%d\n",strlen((char*)crypt_text));
		while(j<crypt_text_len)
		{
			msgbufk[j+23]=portbuffer[j];
			j++;
		}
		if (sendto(sockfd, msgbufk, 23+crypt_text_len, 0, (struct sockaddr *)&cli_addr[hopselk[0]], clilen) < 0) {
			perror("sendto failed");
			return 0;
		}
		memset(msgbufk,'\0',sizeof(msgbufk));
		int rv = recvfrom(sockfd,msgbufk , sizeof(msgbufk), 0, (struct sockaddr *)&recv_addr, &clilen);
		if (rv > 0)
		{
			typek= (char*) (msgbufk + sizeof(struct iphdr));
			struct mycntrlmsgr *msgr = (struct mycntrlmsgr*) (msgbufk + sizeof(struct iphdr)+1);
			fprintf(prof1,"pkt from port: %d, length: %d, contents:0x%02x%04x\n",ntohs(recv_addr.sin_port),rv-20,*typek,msgr->circid);
			fprintf(prof1,"incoming extend-done circuit, incoming: 0x%02x from port: %d\n",ntohs(msgr->circid),ntohs(recv_addr.sin_port));
			fflush(prof1);


		}


	}
	return hopselk[0];




#ifndef CUTT


	/*contrl msg code*/
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
	msg->circid=0x01;
	if(i<(nhops-1))
	{
	msg->portnum=(cli_addr[hopselk[i+1]].sin_port);/*has to be in network byte order*/
	}
	else
		msg->portnum=0xffff;

	printf("Proxy:portn num %d, size : %d \n",msg->portnum,sizeof(msgbuf));

	if (sendto(sockfd, msgbuf, sizeof(msgbuf), 0, (struct sockaddr *)&cli_addr[hopselk[0]], clilen) < 0) {
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
		fprintf(prof1,"incoming extend-done circuit, incoming: 0x%02x from port: %d\n",msg->circid,ntohs(recv_addr.sin_port));
		fflush(prof1);
	}
#endif
	return hopselk[0];

}
