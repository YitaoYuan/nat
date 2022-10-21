
all: nf switch

DEPENDS=src/shared_metadata.h Makefile

build/nf: src/nf.cpp ${DEPENDS} | build
	g++ $< -o $@ -std=c++11 -lpcap -O3 -Wall -Wextra -Wshadow -Wno-unused -Wno-address-of-packed-member

build/nat/tofino/pipe/switch.bfa: src/switch.p4 ${DEPENDS} build/Makefile | build
	cd build; make && make install
	echo "Take up `cat $@ | grep -c stage` stages"

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
	./run.sh

.PHONY: kill
kill:
	./kill_nat.sh
