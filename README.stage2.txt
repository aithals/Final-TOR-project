By:Shashanka Gundmi Vidyadhara Aithal
proja.c has the proxy running in it
router.c has the router running in it
tunnel.c has the tun_alloc() function in it for tunnel allocation
chksm.c has the in_cksum() function in it for icmp check calculation

running code:
just use "make" for compiling 
running ./proja <configfile>

please ignore the messages on the command line.
press ctrl +c and press enter to exit


Stage 2:we create a persistent tunnel interface using the following two commands:
		sudo ip tuntap add dev tun1 mode tun
		sudo ifconfig tun1 10.5.51.2/24 up
		
		and then within the proxy, we attach a fd to this tunnel and recieve any packets that are destined to 10.5.51.x.
		we ping from another terminal to a address: 10.5.51.x. All the icmp packets are received by our inteface. This packet is 
		sent to router. In the router we intrchange the ip address and change icmp type to 0 and check sum to 0. then we send the
		icmp header with payload to checksum calculation. we insert the checksum in the header and the send the packet back to 
		proxy. The proxy writes it back to interface and the ping application receives the echo and shows the response on screen. 

Reused Code: tun_alloc() function from http://backreference.org/2010/03/26/tuntap-interface-tutorial/
			in_cksum() function from ping.c provided in class moodle

Complete: Yes

Portable: No my code is presently not portable for now. If the router is in different computer i need to get the hostname of the proxy
          by calling gethostbyname(). Due to time constraints I was not able to include this. But other than that it should be portable.
~                                                                                                                                          