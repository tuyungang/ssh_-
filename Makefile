main: main.o process.o packet.o
	g++ -g  main.o process.o packet.o -o main -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -ldl -lpthread
main.o: main.cpp process.cpp
	g++ -g -c main.cpp process.cpp -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -ldl -lpthread
process.o: process.cpp packet.cpp
	g++ -g -c process.cpp packet.cpp -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -ldl -lpthread
packet.o: packet.cpp
	g++ -g -c packet.cpp -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -ldl -lpthread

clean:
	@echo "make clean"
	-rm main*.o process*.o packet*.o
	@echo "clean completed"
.PYONE:clean
