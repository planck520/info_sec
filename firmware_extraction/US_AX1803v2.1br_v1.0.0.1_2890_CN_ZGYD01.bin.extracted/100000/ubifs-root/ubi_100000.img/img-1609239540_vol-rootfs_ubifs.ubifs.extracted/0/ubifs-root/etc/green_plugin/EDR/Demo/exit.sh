#! /bin/sh

EDR_PID=`ps | grep hiot_EDR | grep -v 'grep ' | awk '{print $1}'`
WDog_PID=`ps | grep hiot_WDog | grep -v 'grep ' | awk '{print $1}'`

if [ -n "$WDog_PID" ]; then
echo "killing WatchDog process, pid=$WDog_PID"
kill $WDog_PID
fi

if [ -n "$EDR_PID" ]; then
echo "killing EDR process, pid=$EDR_PID"
kill $EDR_PID
fi
