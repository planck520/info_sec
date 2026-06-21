#!/bin/sh

plugin_path=/ctcap/Data
GDHW_TAR_path=/usr/bin/kernelapp_1.2.7.3_TD_AX1806.cpk

#检测网络连接
connect_intertnet_test(){
	ping_result=1
	while [[ "$ping_result" != 0 ]]
	do
		ping -c 1 8.8.8.8 > /dev/null 2>&1
		ping_result=$?
	done
}

deal_plugin(){
	if [ ! -d "$plugin_path" ];then
		mkdir $plugin_path
	fi

	if [ ! -f "$plugin_path/MyPlugin/daemon.sh" ]; then
		cd $plugin_path
		rm -rf ./*
		cd /
		echo "no kernelapp.tar.gz"
		sleep 1
		tar -xzf $GDHW_TAR_path -C $plugin_path
	fi
	
	if [ ! -d "/tmp/gdhw_tmp" ]; then
		mkdir -p /tmp/gdhw_tmp
	fi

	chmod +x $plugin_path/MyPlugin/daemon.sh
	/bin/sh $plugin_path/MyPlugin/daemon.sh &
}

case "$1" in
	start)
		echo "Starting gddx_sdk_deamon..."
		connect_intertnet_test
		deal_plugin
		exit 0
		;;

	*)
		echo "$0: unrecognized option $1"
		exit 1
		;;

esac