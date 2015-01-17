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
		
		I have included a .c file: ini.c which initiaizes the whole setup for projb. TA can optionally use this to
		setup.

Description:We make our tunnel to reveive a ICMP packet whose destination address is in outside world. This
packet is then got by proxy which redirects it to router. The router uses a raw socket to send out this message
to the outside world along with the sendmsg(). The reply is also recived by the router which redirects it back to
proxy and the proxy writes it back to tunnel.The destination ip has to be changed from router interface IP to
eth0(where the ping was done) and checksum has to be calculated again.



a)Reused Code: Only the ones provided in the class website and for sendmsg function i referred this
 /*reference :http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html*/
b)Complete: yes
c)Addressing on the way out of your router: This is just to let the router know from where the packet is coming.
d)Addressing on the way in to the VM: As the router sends the packet to real world it needs an interface of its own
to send and recieve packets from real world.
e)Addressing from the VM to the host:Chages source IP to its own interface and puts in destination when recieves the reply.   

