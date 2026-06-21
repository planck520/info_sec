#!/bin/sh

echo "@@@@@@@@@@@@@@@ mesh_role_slave_wl_set.sh running @@@@@@@@@@@@@@@@@@@@"
# The wl0=5.8g, wl1=2.4g
int2="wl0"
int5="wl1"
tmp_int5="wl1.1"

add_tmp_ap=$1

if [ "$add_tmp_ap" = "add" ]; then
	# Set to temporary slave role
	nvram set td_slave_role_tmp=1
	
	# Set slave role parameters
	#nvram set ${int2}_chanspec=0
	nvram set ${int5}_chanspec=36/80

	#nvram set ${int2}_bw_cap=3
	nvram set ${int5}_bw_cap=7

	nvram set multiap_mode=2

	#nvram set ${int2}_map=4
	nvram set ${int5}_map=4

	# For WPS Push button.
	nvram set lan_wps_oob=disabled
	nvram set wps_action=1
	nvram set wps_proc_status=0
	
	# 5g enable temporary AP
	nvram set ${tmp_int5}_bss_enabled=1

	nvram set ${tmp_int5}_ssid="$(nvram get ${int5}_ssid)"

	nvram set ${tmp_int5}_akm="$(nvram get ${int5}_akm)"

	nvram set ${tmp_int5}_crypto="$(nvram get ${int5}_crypto)"

	nvram set ${tmp_int5}_wpa_psk="$(nvram get ${int5}_wpa_psk)"
else
	# Close temporary slave role
	nvram unset td_slave_role_tmp
	
	# Close 5g temporary AP
	#nvram set ${tmp_int5}_bss_enabled=0
	#ifconfig ${tmp_int5} down
fi
nvram commit
echo "@@@@@@@@@@@@@@@ mesh_role_slave_wl_set.sh done @@@@@@@@@@@@@@@@@@@@@"

