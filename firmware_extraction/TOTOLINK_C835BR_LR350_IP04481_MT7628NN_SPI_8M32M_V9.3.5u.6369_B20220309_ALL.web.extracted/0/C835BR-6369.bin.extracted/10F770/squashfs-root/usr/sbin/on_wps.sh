#!/bin/sh

if [ $# -ne 2 ];
then
    echo "error argument"
		echo "usage: $0 [0:button wps | 1:page wps] [sysled]"
    exit
fi

mode=$1
sysled=$2
count=0
rt_flag=0
wifidualband=0
rt_enable=0
wl_enable=0
rt_wpa_mode=0
wl_wpa_mode=0
rt_macmode=$(nvram get rt_macmode)
wl_macmode=$(nvram get wl_macmode)
rt_enable=$(nvram get rt_radio_x)
rt_wpa_mode=$(nvram get rt_wpa_mode)

rax0_x=rai0

radio_wl=$(ifconfig | grep rax0 | cut -d ' ' -f 0)
if [ -n "$radio_wl" ]; then
        rax0_x=rax0
fi

rt_ssid=$(nvram get rt_ssid)
wl_ssid=$(nvram get wl_ssid)
[ ! -z "$rt_ssid" -a ! -z "$wl_ssid" ] && {
	wifidualband=1
	wl_wpa_mode=$(nvram get wl_wpa_mode)
	wl_enable=$(nvram get wl_radio_x)
	#echo "wifidualband:$wifidualband" > /dev/console
}
echo "wifidualband = $wifidualband" 

echo "rax0_x is  $rax0_x" >/dev/console

echo "wps start. mode is $mode." >/dev/console


if [ $wl_enable -eq 1 -o $rt_enable -eq 1 ] && [ $wl_wpa_mode -eq 2 -o $rt_wpa_mode -eq 2 ]
then
	mtk_gpio -w $sysled 0
fi
case $mode in
0)
	#Button WPS
	
	if [ $wifidualband -eq 0 ]
	then
		echo "ra0 start wps" > /dev/console
		
		if [ "$rt_macmode" != "allow" ]
		then
			iwpriv ra0 set WscStop=1
			iwpriv ra0 set WscConfMode=4
			iwpriv ra0 set WscMode=2
			iwpriv ra0 set WscConfStatus=2
			iwpriv ra0 set WscGetConf=1
		fi
		
		while [ $count -lt 120 ]
		do
			rt_status=`/usr/sbin/wps_status ra0`
			#echo "rt_status:$rt_status" > /dev/console
			[ $rt_status -eq 34 ] && break
			sleep 1
			let "count++"
		done

		if [ $count -lt 120 ]
		then
			echo "ra0 wps succes" > /dev/console
			nvram set rt_wsc_status=2
		else
			echo "ra0 wps time out" > /dev/console
			nvram set rt_wsc_status=1		
		fi
		
		nvram set rt_wsc_beginn=0
	else
		
		if [ $wl_enable -eq 1 ] && [ $wl_wpa_mode -eq 2 ]
		then
			echo "$rax0_x start wps" > /dev/console
			iwpriv ra0 set WscStop=1
			iwpriv $rax0_x set WscStop=1
			
			if [ "$wl_macmode" != "allow" ]
			then
				iwpriv $rax0_x set WscConfMode=4
				iwpriv $rax0_x set WscMode=2
				iwpriv $rax0_x set WscConfStatus=2
				iwpriv $rax0_x set WscGetConf=1
			fi
			
			while [ $count -lt 120 ]
			do
				if [ $count -gt 60 ] && [ $rt_enable -eq 1 ]
				then
				iwpriv $rax0_x set WscStop=1			
				[ $rt_flag -eq 0 ] && {
					if [ "$rt_macmode" != "allow" ]
					then
						iwpriv ra0 set WscConfMode=4
						iwpriv ra0 set WscMode=2
						iwpriv ra0 set WscConfStatus=2
						iwpriv ra0 set WscGetConf=1
					fi
					rt_flag=1
				}
				rt_status=`/usr/sbin/wps_status ra0`
				[ $rt_status -eq 34 ] && break
				else
					wl_status=`/usr/sbin/wps_status $rax0_x`
					#echo "rt_status:$rt_status.wl_status :$wl_status" > /dev/console
					[ $wl_status -eq 34 ] && break		
				fi

				sleep 1
				let "count++"
			done


			if [ $count -lt 120 ]
			then
				echo "wps succes" > /dev/console
				if [ $rt_status -eq 34 ]
				then
					nvram set rt_wsc_status=2
				else
					nvram set wl_wsc_status=2
				fi		
			else
				echo "wps time out" > /dev/console
				nvram set rt_wsc_status=1
				nvram set wl_wsc_status=1
			fi

			nvram set rt_wsc_begin=0
			nvram set wl_wsc_begin=0	
			
			
		elif [ $rt_enable -eq 1 ] && [ $rt_wpa_mode -eq 2 ]
		then
			echo "ra0 start wps" > /dev/console
			iwpriv ra0 set WscStop=1
			iwpriv $rax0_x set WscStop=1
			
			if [ "$rt_macmode" != "allow" ]
			then
				iwpriv ra0 set WscConfMode=4
				iwpriv ra0 set WscMode=2
				iwpriv ra0 set WscConfStatus=2
				iwpriv ra0 set WscGetConf=1
			fi
			
			while [ $count -lt 120 ]
			do
				rt_status=`/usr/sbin/wps_status ra0`
				#echo "rt_status:$rt_status.wl_status :$wl_status" > /dev/console
				[ $rt_status -eq 34 ] && break
				sleep 1
				let "count++"
			done

			if [ $count -lt 120 ]
			then
				echo "wps succes" > /dev/console
				if [ $rt_status -eq 34 ]
				then
					nvram set rt_wsc_status=2
				fi		
			else
				echo "wps time out" > /dev/console
				nvram set rt_wsc_status=1
			fi

			nvram set rt_wsc_begin=0				
		fi
		
	fi
	
	if [ $wl_enable -eq 1 -o $rt_enable -eq 1 ] && [ $wl_wpa_mode -eq 2 -o $rt_wpa_mode -eq 2 ]
	then
		nvram commit
		mtk_gpio -w $sysled 1
	fi
;;
1)
	#Page WPS
	rt_wsc_begin=$(nvram get rt_wsc_begin)
	wl_wsc_begin=$(nvram get wl_wsc_begin)

	if [ $rt_wsc_begin -eq 1 ]
	then
		echo "ra0 start wps" > /dev/console
		mtk_gpio -w $sysled 0
		rt_wsc_mode=$(nvram get rt_wsc_mode)
		iwpriv ra0 set WscStop=1
		if [ $rt_wsc_mode -eq 0 ]
		then
			if [ "$rt_macmode" != "allow" ]
			then
				iwpriv ra0 set WscConfMode=4
				iwpriv ra0 set WscMode=2
				iwpriv ra0 set WscConfStatus=2
				iwpriv ra0 set WscGetConf=1
			fi
				
		else
			if [ "$rt_macmode" != "allow" ]
			then
				rt_wsc_pin=$(nvram get rt_wsc_pin)
				iwpriv ra0 set WscConfMode=7
				iwpriv ra0 set WscPinCode=$rt_wsc_pin
				iwpriv ra0 set WscMode=1
				iwpriv ra0 set WscConfStatus=2
				iwpriv ra0 set WscGetConf=1
			fi
		fi		

		while [ $count -lt 120 ]
		do
			rt_status=`/usr/sbin/wps_status ra0`
			#echo "rt_status:$rt_status" > /dev/console
			[ $rt_status -eq 34 ] && break
			sleep 1
			let "count++"
		done

		if [ $count -lt 120 ]
		then
				echo "ra0 wps success" > /dev/console
				nvram set rt_wsc_status=2
		else
				echo "ra0 wps time out" > /dev/console
				nvram set rt_wsc_status=1
		fi	
		nvram set rt_wsc_beginn=0			
	elif [ $wl_wsc_begin -eq 1 ]
	then
		echo "$rax0_x start wps" > /dev/console
		wl_wsc_mode=$(nvram get wl_wsc_mode)
		iwpriv ra0 set WscStop=1
		if [ $wl_wsc_mode -eq 0 ]
		then
			if [ "$wl_macmode" != "allow" ]
			then
				iwpriv $rax0_x set WscConfMode=4
				iwpriv $rax0_x set WscMode=2
				iwpriv $rax0_x set WscConfStatus=2
				iwpriv $rax0_x set WscGetConf=1
			fi
		else
			if [ "$wl_macmode" != "allow" ]
			then
				wl_wsc_pin=$(nvram get wl_wsc_pin)
				iwpriv $rax0_x set WscConfMode=7
				iwpriv $rax0_x set WscPinCode=$wl_wsc_pin
				iwpriv $rax0_x set WscMode=1
				iwpriv $rax0_x set WscConfStatus=2
				iwpriv $rax0_x set WscGetConf=1
			fi
		fi		

		while [ $count -lt 120 ]
		do
			wl_status=`/usr/sbin/wps_status $rax0_x`
			#echo "wl_status :$wl_status" > /dev/console
			[ $wl_status -eq 34 ] && break
			sleep 1
			let "count++"
		done

		if [ $count -lt 120 ]
		then
				echo "$rax0_x wps success" > /dev/console
				nvram set wl_wsc_status=2
		else
				echo "$rax0_x wps time out" > /dev/console
				nvram set wl_wsc_status=1
		fi
		nvram set wl_wsc_begin=0	
	fi
	nvram commit
	mtk_gpio -w $sysled 1
;;
*)
echo "error argument"
echo "0--------Button WPS;1--------Page WPS"
esac
