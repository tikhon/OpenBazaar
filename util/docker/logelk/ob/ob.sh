#!/bin/bash
LOG_PATH=/bazaar/logs/production.log
# touch log file before bash openbazaar start to keep tail -f work
mkdir -p /bazaar/logs && touch $LOG_PATH
IP=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}')
cd /bazaar && ./openbazaar -j --disable-open-browser -k $IP $RUNSH_ARGS start && tail -f $LOG_PATH
