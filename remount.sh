#!/bin/sh

sudo fusermount -u ~/test/fuse
./memfs ~/test/fuse
sleep 1
ps aux | grep memfs | grep grep -v
