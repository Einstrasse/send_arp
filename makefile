spoofer: spoofer.o infofetcher.o
	gcc -o spoofer spoofer.o infofetcher.o -Wall -lpcap

spoofer.o: spoofer.c
	gcc -c -o spoofer.o spoofer.c -Wall
infofetcher.o: infofetcher.c
	gcc -c -o infofetcher.o infofetcher.c -Wall

clean:
	rm ifconfig *.o