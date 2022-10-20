#!/bin/bash

DIR=$(dirname $0)

rsync -rv -e ssh --exclude "build*" --exclude "tmp*" --exclude ".*" -r $DIR switch3:~/yyt/nat

