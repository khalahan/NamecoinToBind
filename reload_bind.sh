#!/bin/bash

while true; do
  if [ -n "`find /etc/bind/dotbit -mmin -2`" ]; then
    echo `date`
    /etc/init.d/bind9 reload
    sleep 2s
    /etc/init.d/bind9 start
  fi
  sleep 1m
done

