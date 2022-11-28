#!/bin/bash

FILE_DIR=`cd $(dirname $0); pwd`
. $FILE_DIR/utils.sh

create_dir()
{
  if [ ! \( -e $1 \) ];
  then 
    echo_r "mkdir -p $1"
  fi
}

set -e

if [ $# -ne 2 ];
then 
	echo_e "Usage: compile_p4.sh <PROGRAM_PATH> <BUILD_DIR_PATH>"
	exit 1
fi

P_PATH=$(realpath -m $1)
B_PATH=$(realpath -m $2)
BASE_NAME=$(basename $1)
TAIL=${BASE_NAME#*.}
NAME=${BASE_NAME%%.*}

if [ ! \( -e $P_PATH \) ];
then
  echo_e "File $P_PATH does not exist."
  exit 1
fi


if [ $TAIL == "cpp" ];
then 
  create_dir $B_PATH
  COMPILE_ARGS="-std=c++11 -lpcap -O3 -Wall -Wextra -Wshadow -Wno-unused -Wno-address-of-packed-member"
  echo_r "g++ $P_PATH -o $B_PATH/$NAME ${COMPILE_ARGS} "
  exit 0
fi

if [ $TAIL != "p4" ];
then 
  echo_e "Unsupported file type."
  exit 1
fi

create_dir $B_PATH
echo_r "cd $B_PATH"
echo_r "cmake $SDE/p4studio/ \
  -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL \
  -DCMAKE_MODULE_PATH=$SDE/cmake \
  -DP4_NAME=$NAME \
  -DP4_PATH=$P_PATH \
"
BFA_PATH=$B_PATH/$NAME/tofino/pipe/$NAME.bfa
if [ -e $BFA_PATH ];
then
  echo_r "make clean"
fi
echo_r "make && make install"
echo_i "Take up `cat $BFA_PATH | grep -c -E "stage.+ingress"` ingress stages"
echo_i "Take up `cat $BFA_PATH | grep -c -E "stage.+egress"` egress stages"