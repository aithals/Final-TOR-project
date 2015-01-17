projc: projc.o router.o tunnel.o chksm.o creat_s5.o creat_s6.o creat_s8.o aes.o router_s6.o router_s7.o router_s8.o router_s9.o
	gcc -o projc -g projc.o router.o tunnel.o chksm.o creat_s5.o creat_s6.o creat_s8.o aes.o router_s6.o router_s7.o router_s8.o router_s9.o -lcrypto -lm

projc.o: projc.c tunnel.h
	gcc -g -c -Wall projc.c

router.o: router.c tunnel.h key.h
	gcc -g -c -Wall router.c

tunnel.o: tunnel.c tunnel.h
	gcc -g -c -Wall tunnel.c

chksm.o: chksm.c tunnel.h
	gcc -g -c -Wall chksm.c

creat_s5.o: creat_s5.c tunnel.h
	gcc -g -c -Wall creat_s5.c
	
creat_s6.o: creat_s6.c tunnel.h
	gcc -g -c -Wall creat_s6.c -lm
	
creat_s8.o: creat_s8.c tunnel.h
	gcc -g -c -Wall creat_s8.c -lm
	
aes.o: aes.c 
	gcc -g -c -Wall aes.c -lcrypto
	
router_s6.o: router_s6.c tunnel.h key.h
	gcc -g -c -Wall router_s6.c
	
router_s7.o: router_s7.c tunnel.h key.h
	gcc -g -c -Wall router_s7.c
	
router_s8.o: router_s8.c tunnel.h key.h
	gcc -g -c -Wall router_s8.c
	
router_s9.o: router_s9.c tunnel.h key.h
	gcc -g -c -Wall router_s9.c			 
	
clean:
	rm -f *.o projc

