#!/bin/bash
echo "uid=$(id -u)"
ls -ld /run/tor /run/tor-instances/default 2>&1
ls -l /run/tor /run/tor-instances/default 2>&1 | awk '{print $1, $3, $4, $NF}'
echo "instance torrc control lines:"
grep -nE '^\s*(ControlPort|ControlSocket|CookieAuth|CookieAuthFile)' /etc/tor/instances/default/torrc 2>&1
ls /etc/privoxy/ | grep -c ratriyx-bak
