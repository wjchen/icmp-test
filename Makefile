all:
	gcc -Wall -O2 icmp_server.c md5.c key_gen.c rc4.c -o server
	gcc -Wall -O2 icmp_client.c md5.c key_gen.c rc4.c timer.c -o client -lpthread

clean:
	rm client server
