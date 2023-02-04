#!/bin/sh
/usr/local/bin/redis-init.sh &
/usr/local/bin/docker-entrypoint.sh $1