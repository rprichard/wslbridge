all : ../out/wslbridge.exe

../out/wslbridge.exe : wslbridge.cc ../common/SocketIo.cc ../common/SocketIo.h ../VERSION.txt Makefile
	mkdir -p ../out
	g++ -std=c++11 -fno-exceptions \
		-static -static-libgcc -static-libstdc++ \
		-D_GNU_SOURCE -D_WIN32_WINNT=0x0600 -DUNICODE -D_UNICODE \
		-DWSLBRIDGE_VERSION=$(shell cat ../VERSION.txt) \
		-Wall -O2 $< ../common/SocketIo.cc -o $@
	strip $@
