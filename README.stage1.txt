By:Shashanka Gundmi Vidyadhara Aithal
Proja.c has the proxy running in it
Router.c has the router running in it
Stage 1:In stage 1 we used fork function.The child process acted as the router while the parent acted as the proxy.
The proxy gets a dynamic UDP  port assigned to it by calling the getsockname(). The parent socket file descriptor is closed by
child and it creates its own UDP socket and gets a dynamic port by calling getsockname(); Router then sends a "im up" message to the proxy

running code:
just use "make" for compiling 
running ./proja <configfile>

please ignore the messages on the command line.
press ctrl +c and press enter to exit

Rused Code: None

Complete: Yes

Portable: No my code is presently not portable for now. If the router is in different computer i need to get the hostname of the proxy
	  by calling gethostbyname(). Due to time constraints I was not able to include this. But other than that it should be portable.
