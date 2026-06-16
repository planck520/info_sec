#!/bin/sh

case "$1" in
	start)
		echo "Starting cfmd..."
		/bin/cfmd &
		exit 0
		;;

	stop)
		echo "Stopping cfmd..."
		killall -9 cfmd
		exit 0
		;;

	*)
		echo "$0: unrecognized option $1"
		exit 1
		;;

esac

