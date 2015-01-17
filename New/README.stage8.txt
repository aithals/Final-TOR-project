By:Shashanka Gundmi Vidyadhara Aithal
projc.c has the proxy running in it
router.c has the router running in it
tunnel.c has the tun_alloc() function in it for tunnel allocation
chksm.c has the in_cksum() function in it for icmp check calculation
creat_s5.c has the circuit creation code for stage 5
creat_s6.c has the circuit creation for stage 6 and 9
creat_s8.c has the circuit creation for stage 8
router_s6.c has code that takes care of the interactions between routers over the UDP port for stage 6.
router_s7.c has code that takes care of the interactions between routers over the UDP port for stage 7.
router_s8.c has code that takes care of the interactions between routers over the UDP port for stage 8.
router_s9.c has code that takes care of the interactions between routers over the UDP port for stage 9.
aes.c contains encryption and decryption code.
key.h has a few variables that are shared between different files
tunnel.h has the structures used
 
running code:
just use "make" for compiling 
running ./projc <configfile>


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
		sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
		sudo ip route add table 9 to 128.9.160.91 dev tun1
				
		I have included a .c file: ini.c which initiaizes the whole setup for projb. TA can optionally use this to
		setup.
		
Description: Here we support both TCP and ICMP with new unique circuit created for each flow of TCP and UDP. A 5 tupple flow is
considered here. My code creates unique keys for each circuit that is being created for each new flow that it encounters.

a)Reused Code: Only the ones provided in the class website and for sendmsg function i referred this
 /*reference :http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html*/
b)Complete: yes
c)Here the circuits are formed based on the flows. If the packets get off the circuit and go to random routers
the encryption and decryption sequence gets messed up as the routers wont know which key to use to decrypt.
d)If the packets are sent slowly there might be enough time to establish a circuit and obtain keys for each time a packet comes along which might not be
the case if the packets are coming in fast.
e)If the nodes are in the outside world the delay might be much more and circuit establishment would take longer time. Here
making a circuit for each packet might not be successfull .