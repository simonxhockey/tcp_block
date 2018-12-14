all: tcp_block

tcp_block: tcp_block.o
	g++ -g -o tcp_block tcp_block.o -lpcap

tcp_block.o : tcp_block.cpp
	g++ -c -g -o tcp_block.o tcp_block.cpp

clean:
	rm -f tcp_block
	rm -f *.o


