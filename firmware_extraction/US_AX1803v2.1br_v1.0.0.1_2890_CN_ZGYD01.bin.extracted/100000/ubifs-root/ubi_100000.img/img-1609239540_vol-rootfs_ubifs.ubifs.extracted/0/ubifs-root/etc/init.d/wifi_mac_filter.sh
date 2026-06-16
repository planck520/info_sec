#!/bin/bash

mode=""
nvram_mac_filter_list=""
wl0_assolist=""
wl1_assolist=""

get_wifi_mac_filter_mode()
{
	mode=$(nvram get wl0_macmode)
}

get_nvram_mac_filter()
{
	nvram_mac_filter_list=$(nvram get wl0_maclist)
	nvram_mac_filter_list=$(eval echo $nvram_mac_filter_list)
	nvram_mac_filter_list="${nvram_mac_filter_list} "
}

get_assolist()
{
	wl0_assolist=$(wl -i wl0 assoclist | grep -o  "[a-f0-9A-F]\\([a-f0-9A-F]\\:[a-f0-9A-F]\\)\\{5\\}[a-f0-9A-F]")
	wl1_assolist=$(wl -i wl1 assoclist | grep -o  "[a-f0-9A-F]\\([a-f0-9A-F]\\:[a-f0-9A-F]\\)\\{5\\}[a-f0-9A-F]")
}

set_mac_filter_rule()
{
	$(wl -i wl0 mac none)
	$(wl -i wl1 mac none)
	i=1
	IFS=$'\n\n'
	while(true)
	do
		rule_mac=$(echo $nvram_mac_filter_list|cut -d " " -f$i)
		if [ "$rule_mac" != "" ];
		then
			let "i=i+1"
			$(wl -i wl1 mac $rule_mac)
			$(wl -i wl0 mac $rule_mac)
		else
			break
		fi
	done
	
	if [ "$mode" == "allow" ];then
		$(wl -i wl0 macmode 2)
		$(wl -i wl1 macmode 2)
	else
		$(wl -i wl0 macmode 1)
		$(wl -i wl1 macmode 1)
	fi
	

}

disassoc_black_sta()
{
	for assoc_sta in $wl0_assolist
	do
		ret=$(echo $nvram_mac_filter_list | grep -i $assoc_sta)
		if [ "$ret" != "" ];then
			$(wl -i wl0 disassoc $assoc_sta)
		fi
	done
	for assoc_sta in $wl1_assolist
	do
		ret=$(echo $nvram_mac_filter_list | grep -i $assoc_sta)
		if [ "$ret" != "" ];then
			$(wl -i wl1  disassoc $assoc_sta)
		fi
	done
}

disassoc_white_sta()
{
	for assoc_sta in $wl0_assolist
	do
		ret=$(echo $nvram_mac_filter_list | grep -i $assoc_sta)
		if [ "$ret" == "" ];then
			$(wl -i wl0 disassoc  $assoc_sta)
		fi
	done
	for assoc_sta in $wl1_assolist
	do
		ret=$(echo $nvram_mac_filter_list | grep -i $assoc_sta)
		if [ "$ret" == "" ];then
			$(wl -i wl1 disassoc  $assoc_sta)
		fi
	done
}

disassoc_sta()
{
	if [ "$mode" == "allow" ];then
		disassoc_white_sta
	else
		disassoc_black_sta
	fi
}

main()
{
	sleep 1
	get_wifi_mac_filter_mode
	get_nvram_mac_filter
	set_mac_filter_rule
	get_assolist
	disassoc_sta
}

main