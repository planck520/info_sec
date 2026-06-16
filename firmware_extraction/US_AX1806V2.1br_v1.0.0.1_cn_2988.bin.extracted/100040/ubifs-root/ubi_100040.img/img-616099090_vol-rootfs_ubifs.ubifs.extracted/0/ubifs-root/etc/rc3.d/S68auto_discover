#!/bin/sh

case "$1" in
	start)
		echo "Starting auto_discover..."
		/bin/auto_discover &
		exit 0
		;;

	stop)
		echo "Stopping auto_discover..."
		killall -9 auto_discover
		exit 0
		;;

	*)
		echo "$0: unrecognized option $1"
		exit 1
		;;

esac

