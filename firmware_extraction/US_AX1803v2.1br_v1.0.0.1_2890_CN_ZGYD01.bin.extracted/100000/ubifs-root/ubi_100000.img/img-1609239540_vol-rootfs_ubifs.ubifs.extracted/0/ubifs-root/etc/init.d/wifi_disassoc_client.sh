#!/bin/bash

wl_list=""
assolist=""
multiap_mode=""

disassoc()
{
	wl_list=$(ifconfig |grep -o "wl[.0-9]*")
	multiap_mode=$(nvram get multiap_mode)
	
	for wl in $wl_list
	do
		if [ "$multiap_mode" == "2" ] && [ "$wl" == "wl1" ];then
			continue
		fi
		assoclist=$(wl -i $wl assoclist | grep -o  "[a-f0-9A-F]\\([a-f0-9A-F]\\:[a-f0-9A-F]\\)\\{5\\}[a-f0-9A-F]")
		if [ "$assoclist" != "" ];then
			for sta in $assoclist
			do
				echo wl -i $wl disassoc  $sta
				$(wl -i $wl disassoc  $sta)
			done
		fi
	done 
}

disassoc