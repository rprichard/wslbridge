all : ../out/wslbridge-backend

../out/wslbridge-backend : wslbridge-backend.cc ../common/SocketIo.cc ../common/SocketIo.h
	mkdir -p ../out
	g++ -std=c++11 -fno-exceptions -D_GNU_SOURCE -Wall -O2 $< ../common/SocketIo.cc -o $@ -lutil -pthread
