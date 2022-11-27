
all: nf switch

P4_DEP=src/shared_metadata.h
CPP_DEP=src/checksum.hpp src/hash.hpp src/hdr.h src/heavy_hitter.hpp src/list.hpp src/type.h src/shared_metadata.h

COMPILE_ARGS=-std=c++11 -lpcap -O3 -Wall -Wextra -Wshadow -Wno-unused -Wno-address-of-packed-member

build/nat/nf: src/nat.cpp ${CPP_DEP} Makefile 
	rm -r build
	mkdir build
	g++ $< -o $@ ${COMPILE_ARGS}

build/nat/nat/tofino/pipe/nat.bfa: src/nat.p4 ${P4_DEP} Makefile
	rm -r build
	mkdir build
	./mycmake.sh
	cd build; make && make install
	@echo "Take up `cat $@ | grep -c -E "stage.+ingress"` ingress stages"
	@echo "Take up `cat $@ | grep -c -E "stage.+egress"` egress stages"

.PHONY: nf 
nf: build/nf

.PHONY: switch
switch: build/nat/tofino/pipe/nat.bfa

.PHONY: run
run: switch
	./run.sh nat bfrt_table_init.py

.PHONY: kill
kill:
	./kill.sh nat

.PHONY: clean
clean:
	rm -r ./build
