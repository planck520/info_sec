#!/bin/bash

agent_info_array=""
dev_name=""
p_dev_name=""
self_addr=""
dev_role=""
get_dev_cmd=""

accesstype_5G="5g"
accesstype_2G="2g"
accesstype_wired="wired"

init_var()
{
	agent_info_array="{\"child_devices\":["
	dev_name=$(cfm get sys.targets)
}

get_self_addr()
{
	self_addr=$(ifconfig br0 | grep -o "[a-f0-9A-F]\\([a-f0-9A-F]\\:[a-f0-9A-F]\\)\\{5\\}[a-f0-9A-F]")
}

init_var()
{
	agent_info_array="{\"child_devices\":["
	dev_name=$(cfm get sys.targets)
	dev_role=$(cfm get multiap_mode)
}

end_var()
{
	agent_info_array=$(echo ${agent_info_array%,*})
	agent_info_array="${agent_info_array}]}"
}


get_agent()
{
	IFS_old=$IFS
	IFS=$'\n'
	if [ x"$dev_role" == x"2" ];then
		get_dev_cmd=$(wb_cli -s info | grep "br0")
	else
		get_dev_cmd=$(wb_cli -m info | grep "br0")
	fi
	for line in $get_dev_cmd
	do
	    tmp_dev_info=""
		tmp_br0_addr=""
		tmp_dev_ip=""
		tmp_rssi=""
        tmp_acc_type=""
        tmp_p_mac=""
        tmp_p_role=""


        if [ x"$dev_role" != x"2" ];then
            dev_name="Agent"
        fi


		tmp_dev_info=$(echo ${line#*=})
        tmp_br0_addr=$(echo $tmp_dev_info | grep -o "[a-f0-9A-F]\\([a-f0-9A-F]\\:[a-f0-9A-F]\\)\\{5\\}[a-f0-9A-F]")
        tmp_br0_addr=$(echo ${tmp_br0_addr:0:17})

		#result=$(echo $tmp_br0_addr | grep -i "${self_addr}")
		#if [ "$result" != "" ];then
		#	continue
		#fi
		tmp_dev_info=$(echo ${tmp_dev_info#*=})
		tmp_dev_ip=$(echo $tmp_dev_info | grep -Eoe "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")
        tmp_dev_info=$(echo ${tmp_dev_info#*=})
		tmp_rssi=$(echo ${tmp_dev_info:0:2})

        tmp_dev_info=$(echo ${tmp_dev_info#*=})
        result1=$(echo $tmp_dev_info | grep -o "${accesstype_5G}")
        if [ "$result1" != "" ];then 
            tmp_acc_type="2"
        else
            result2=$(echo $tmp_dev_info | grep -o "${accesstype_2G}")
            if [ "$result2" != "" ];then 
                tmp_acc_type="1"
            else 
                result3=$(echo $tmp_dev_info | grep -o "${accesstype_wired}")
                if [ "$result3" != "" ];then 
                    tmp_acc_type="0"
                fi
            fi
        fi

        tmp_dev_info=$(echo ${tmp_dev_info#*=})
        tmp_p_mac=$(echo $tmp_dev_info | grep -o "[a-f0-9A-F]\\([a-f0-9A-F]\\:[a-f0-9A-F]\\)\\{5\\}[a-f0-9A-F]")

        tmp_p_role=$(echo ${tmp_dev_info#*=})
        if [ "$tmp_p_role" != "0" ];then
            p_dev_name="Controller"
        else
            p_dev_name="Agent"
        fi

        
		if [ "$tmp_br0_addr" != "" -a "$tmp_br0_addr" != "0:0:0:0" -a "$tmp_dev_ip" != ""  -a "$tmp_dev_ip" != "0.0.0.0" -a "$tmp_p_mac" != "00:00:00:00:00:00" ];then
			mac_name=$(echo ${tmp_br0_addr:12:16})
			mac_name="$(echo $mac_name | grep -o '^[^:]*')$(echo $mac_name | grep -o '[^:]*$')"
			p_mac_name=$(echo ${tmp_p_mac:12:16})
			p_mac_name="$(echo $p_mac_name | grep -o '^[^:]*')$(echo $p_mac_name | grep -o '[^:]*$')"
			devname="${dev_name}-${mac_name}"
			entry="{\"device_name\":\"$devname\",\"ip_addr\":\"$tmp_dev_ip\",\"mac_address\":\"$tmp_br0_addr\",\"rssi\":\"-$tmp_rssi\",\"p_wmac\":\"$tmp_p_mac\",\"accesstype\":\"$tmp_acc_type\",\"p_role\":\"${p_dev_name}-${p_mac_name}\"},"
			agent_info_array="${agent_info_array}${entry}" 
		fi
	done
	IFS=$IFS_old
}

pull_topology_file()
{
	#echo "agent_info_array="$agent_info_array
	echo $agent_info_array > /tmp/dev_json.txt
}

shoubuliao_main()
{
	init_var
	get_self_addr
	get_agent 
    end_var
    pull_topology_file
}

while :; do
	shoubuliao_main
	sleep 5
done
