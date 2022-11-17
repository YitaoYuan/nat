#!/bin/bash

DIR=$(dirname $0)
. $DIR/utils.sh

IF=ens10f1
echo_r "sudo tcpdump -e -n -X -vv -i $IF"
