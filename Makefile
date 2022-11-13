
all: nf switch

DEPENDS=src/shared_metadata.h Makefile

COMPILE_ARGS=-std=c++11 -lpcap -O3 -Wall -Wextra -Wshadow -Wno-unused -Wno-address-of-packed-member

build/nf: src/nf.cpp ${DEPENDS} | build
	g++ $< -o $@ ${COMPILE_ARGS}

build/nat/tofino/pipe/switch.bfa: src/switch.p4 ${DEPENDS} build/Makefile | build
	cd build; make && make install
	@echo "Take up `cat $@ | grep -c -E "stage.+ingress"` ingress stages"
	@echo "Take up `cat $@ | grep -c -E "stage.+egress"` egress stages"

build/Makefile: mycmake.sh | build
	./mycmake.sh

build:
	mkdir -p build
	

.PHONY: nf 
nf: build/nf

.PHONY: switch
switch: build/nat/tofino/pipe/switch.bfa

.PHONY: run
run: switch
	./run.sh nat bfrt_table_init.py

.PHONY: kill
kill:
	./kill.sh nat
