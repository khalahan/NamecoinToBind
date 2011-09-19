#!/bin/bash

while true; do
  su -c '/usr/bin/php-cgi ./namescan.php' www-data
  if [ -n "`find /etc/bind/namecoin -mmin -2`" ]; then
    echo `date`
    /etc/init.d/bind9 reload
    sleep 2s
    /etc/init.d/bind9 start
  fi
  sleep 1m
done

