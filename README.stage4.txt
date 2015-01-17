By:Shashanka Gundmi Vidyadhara Aithal
proja.c has the proxy running in it
router.c has the router running in it
tunnel.c has the tun_alloc() function in it for tunnel allocation
chksm.c has the in_cksum() function in it for icmp check calculation


running code:
just use "make" for compiling 
running ./proja <configfile>


please ignore the messages on the command line stdout.
press ctrl +c and press enter to exit

Stage 3:initial setup:
		sudo ip tuntap add dev tun1 mode tun
		sudo ifconfig tun1 10.5.51.2/24 up
		sudo ip rule add from $IP_OF_ETH0 table 9 priority 8
		sudo ip route add table 9 to 18/8 dev tun1
		sudo ip route add table 9 to 128/8 dev tun1
		sudo ifconfig eth1 192.168.201.2/24 up
		sudo ifconfig eth2 192.168.202.2/24 up
		sudo ifconfig eth3 192.168.203.2/24 up
		sudo ifconfig eth4 192.168.204.2/24 up
		sudo ifconfig eth5 192.168.205.2/24 up
		sudo ifconfig eth6 192.168.206.2/24 up
				
		I have included a .c file: ini.c which initiaizes the whole setup for projb. TA can optionally use this to
		setup.
		
Description: Similar to stage 3 but we use fork multiple times at proxy to get multiple routers. We decide on the 
destinatin IP (using %(no of routers) to decide which router should proxy select to send the recvd ICMP pkt.


a)Reused Code: Only the ones provided in the class website and for sendmsg function i referred this
 /*reference :http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html*/
b)Complete: yes
c)Router Selection: 1)The IP addresses decide which router does the proxy select therefore this kind of loadbalancing 
as different flows(differeny destinations) go to different routers if the probability of all types of flows are equal;
2)yes
3)Since we are just using %(num of routers) for selecting routers at proxy, If the dst of arriving flows have same 
value for %(num of routers) ,there is imbalance in load distribution.