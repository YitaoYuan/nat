#!/bin/bash

DIR=$(dirname $0)

scp ${DIR}/src/* switch:~/yyt/nat/src/
