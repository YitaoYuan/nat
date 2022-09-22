
all: build/nf build/switch_build_tag

DEPENDS=src/shared_metadata.h Makefile

build/nf: src/nf.cpp ${DEPENDS} | build
	g++ $< -o $@ -std=c++11 -lpcap -g3 -Wall -Wextra -Wshadow -Wno-unused -Wno-address-of-packed-member

build/switch_build_tag: src/switch.p4 ${DEPENDS} | build
	./compile_for_tofino.sh && touch build/switch_build_tag

build:
	mkdir build

.PHONY: nf 
nf: build/nf

.PHONY: switch
switch: build/switch_build_tag
