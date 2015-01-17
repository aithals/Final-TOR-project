By:Shashanka Gundmi Vidyadhara Aithal
proja.c has the proxy running in it
router.c has the router running in it
tunnel.c has the tun_alloc() function in it for tunnel allocation
chksm.c has the in_cksum() function in it for icmp check calculation
creat_s5.c has the circuit creation code for stage 5
 
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
		
Description: In stage 5 we do Onion routing without encryption. We randomly select the routers to be the hops for routing.
 We build a circuit similar to the dingledine paper and then relay the data through the circuit . The last hop then transmits
 the data to real world and recieves the reply back. It then again relays back this packet through the same circuit backwards.
 Finally the proxy writes it back to tunnel.
 
a)Reused Code: Only the ones provided in the class website and for sendmsg function i referred this
 /*reference :http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html*/
b)Complete: yes
c)This to maintain annonymity of the original source.  