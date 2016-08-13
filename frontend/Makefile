all : ../out/wslbridge.exe

../out/wslbridge.exe : wslbridge.cc ../common/SocketIo.cc ../common/SocketIo.h
	mkdir -p ../out
	g++ -D_GNU_SOURCE -Wall -std=c++11 -O2 $< ../common/SocketIo.cc -o $@
