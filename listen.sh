#!/bin/bash
IF=ens10f1
sudo tcpdump -e -n -X -vv -i $IF
