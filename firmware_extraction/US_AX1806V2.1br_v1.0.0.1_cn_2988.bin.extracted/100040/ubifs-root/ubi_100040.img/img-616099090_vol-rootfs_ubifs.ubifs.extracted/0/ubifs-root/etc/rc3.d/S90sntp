#!/bin/sh
case "$1" in
	start)
		echo "wangjianqiang sntp.sh start success"
        if [ -x /bin/tdsntp ]; then
            echo "Start TDsntp!"
        else
            /bin/sntp -s cn.pool.ntp.org -t 'Beijing, Chongquing' &
        fi
        wdtctl -t 10 -d start
		exit 0
		;;

	stop)
		echo "wangjianqiang sntp.sh stop error"
		echo "sntp stop"
        if [ -x /bin/tdsntp ]; then
            echo "Stop TDsntp!"
        else
            killall -9 sntp
        fi
        exit 1
		;;
	*)
		echo "wangjianqiang sntp.sh start error"
		echo "bcmbasedrivers: unrecognized option $1"
		exit 1
		;;

esac
	