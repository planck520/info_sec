#!/bin/bash

ip_addr=""
ip_change=0

get_ip_addr_by_if()
{
	if_info=$(ifconfig $1 | grep "inet addr:")
	if_info=${if_info%%B*}
	ip_addr=$(echo $if_info | grep -Eoe "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")
}

check_dev_ip_change()
{
	work_mode=$(cfm get sys.workmode)
	if [ "router" == "${work_mode}" ]
	then
		get_ip_addr_by_if "eth0.1"
	else
		get_ip_addr_by_if "br0"
	fi

	if [ "router" == "${work_mode}" -a "" != "$ip_addr" ]
	then
		ip_change=1
	elif [ "router" != "${work_mode}" -a "" != "$ip_addr" -a "192.168.2.1" != "$ip_addr" ]
	then
		ip_change=1
	else
		ip_change=0
	fi
}

be_going_to_change_multiap_mode()
{
	while(true)
	do
		#fast_flag=$(cfm get sys.quickset.cfg)
		#if [ x"0" == x"${fast_flag}" ]
		#then
		#	break;
		#fi
		multiap_mode=$(cfm get multiap_mode)
		if [ x"3" == x"${multiap_mode}" ]
		then
			break;
		fi
		wl_start_ok=$(nvram get wl_start_ok)
		if [ x"1" != x"${wl_start_ok}" ]
		then
			count=0
			continue;
		fi
		check_dev_ip_change
		if [ x"1" == x"${ip_change}" ]
		then
			count=$(($count+1))
			find_controller=$(nvram get find_controller)
			if [ "1" == "${find_controller}" ]
			then
				#$(cfm post netctrl 9?op=600)
				break;
			elif [ "1" != "${find_controller}" -a $count -gt 8 ]
			then
				$(cfm post netctrl 9?op=500)
				break;
			fi
		else
			count=0
		fi
	sleep 2
	done
}

be_going_to_change_multiap_mode

