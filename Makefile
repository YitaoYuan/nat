
all: build/nf build/switch.json

DEPENDS=src/shared_metadata.h Makefile

build/nf: src/nf.cpp ${DEPENDS} | build
	g++ $< -o $@ -std=c++11 -lpcap -g3 -Wall -Wextra -Wshadow -Wno-unused -Wno-address-of-packed-member

build/switch.json: src/switch.p4 ${DEPENDS} | build
	p4c -a v1model -b bmv2 $< -o build

build:
	mkdir build
