#!/bin/sh

set -m
redis-server --include /etc/redis.conf &
sleep 5
cat /usr/local/bin/ioclib.lua | redis-cli -x FUNCTION LOAD REPLACE
fg %1