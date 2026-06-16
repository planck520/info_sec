#!/bin/bash

wl_list=""
assolist=""
multiap_mode=""

disassoc()
{
	wl_list=$(ifconfig |grep -o "wl[.0-9]*")
	for wl in $wl_list
	do
		assoclist=$(wl -i $wl assoclist | grep -o  "[a-f0-9A-F]\\([a-f0-9A-F]\\:[a-f0-9A-F]\\)\\{5\\}[a-f0-9A-F]")
		if [ "$assoclist" != "" ];then
			for sta in $assoclist
			do
				if [ $sta == $1 ];then
					echo wl -i $wl disassoc  $sta
					$(wl -i $wl disassoc  $sta)
					exit
				fi
			done
		fi
	done 
}

disassoc $1