#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void main()
{	char a[20];
	char buf[55];
	FILE *fp;
	memset(a,'\0',sizeof(a));
	memset(buf,'\0',sizeof(buf));
	system("sudo ip tuntap add dev tun1 mode tun");
	system("sudo ifconfig tun1 10.5.51.2/24 up");
	fp=popen("/sbin/ifconfig eth0 |grep 'inet '|cut -d ' ' -f 10-11|awk '{ print $1 }'","r");
	if (fp == NULL) {
      		printf("Failed to run command\n" );
      		exit -1;
  	}

  	fgets(a, sizeof(a), fp); 
	char * pch=strchr(a,'\n');
	/*if(pch == NULL)
	{printf("NULLLLLL\n");
	}
	pch='\0';*/
	a[strlen(a)-1]='\0';
	printf("%s siz%d   len%d",a,sizeof(a),strlen(a));
	sprintf(buf,"sudo ip rule add from %s table 9 priority 8",a);
	system(buf);
	system("sudo ip route add table 9 to 18/8 dev tun1");
system("sudo ip route add table 9 to 128.30/16 dev tun1");

system("sudo ifconfig eth1 192.168.201.2/24 up");
system("sudo ifconfig eth2 192.168.202.2/24 up");
system("sudo ifconfig eth3 192.168.203.2/24 up");
system("sudo ifconfig eth4 192.168.204.2/24 up");
system("sudo ifconfig eth5 192.168.205.2/24 up");
system("sudo ifconfig eth6 192.168.206.2/24 up");
system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP");
system("sudo ip route add table 9 to 128.9.160.91 dev tun1");
}


