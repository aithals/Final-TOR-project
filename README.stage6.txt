By:Shashanka Gundmi Vidyadhara Aithal
proja.c has the proxy running in it
router.c has the router running in it
tunnel.c has the tun_alloc() function in it for tunnel allocation
chksm.c has the in_cksum() function in it for icmp check calculation
creat_s5.c has the circuit creation code for stage 5
creat_s6.c has the circuit creation for stage 6
router_s6.c has code that takes care of the interactions between routers over the UDP port.
aes.c contains encryption and decryption code
 
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
		
Description: Same concept as stage 5 but with encryption using AES library. Each router gets a key associated with it.
While getting the key the previous hop always knows the key of next hop but all other hops wont know as it would be 
encrypted with keys till the prev hop's key. Each hop only decrypts once and forwards it next hop.
All of these keys are available at proxy. Proxy as soon as it gets the data from tunnel stores the source IP and clears it out
in the actual packet to maintain annonymity.Proxy encrypts the relay data with all these keys starting from lasthop to
firsthop. Each hop only decrypts once and the forwards it to nexthop. The actual data is available after last hop
decrypts and the last hop sends it outside word like in previous stages. The reply received from real world is then
encrypted at each hop as it goes back in circuit. The proxy decrypts each layer staring from forst hop key to last hop key
It then writes the destination IP(using the stored IP before), calculate checksum and writes it to tunnel.  

a)Reused Code: Only the ones provided in the class website and for sendmsg function i referred this
 /*reference :http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html*/
b)Complete: yes

		