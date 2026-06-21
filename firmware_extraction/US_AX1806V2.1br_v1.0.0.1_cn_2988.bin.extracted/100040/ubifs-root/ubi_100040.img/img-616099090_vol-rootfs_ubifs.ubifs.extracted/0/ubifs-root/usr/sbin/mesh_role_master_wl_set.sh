#!/bin/sh
echo "@@@@@@@@@@@@@@@ mesh_role_master_wl_set.sh running @@@@@@@@@@@@@@@@@@@@"
intf2="wl0"
intf5="wl1"
intf5_tmp="wl1.1"

# Close temporary slave role
nvram unset td_slave_role_tmp

# Close 5g temporary AP
nvram set ${intf5}_map=1
nvram set ${intf5_tmp}_map=2
nvram set ${intf5_tmp}_bss_enabled=0

# Set master role parameters
#nvram set ${intf2}_chanspec=0
nvram set ${intf5}_chanspec=0
#nvram set ${intf2}_bw_cap=3
#nvram set ${intf5}_bw_cap=7

nvram set multiap_mode=3
nvram set map_bss_names="fh_2g fh_5g bh"
nvram set fh_2g_map=1
nvram set fh_5g_map=1
nvram set bh_map=2

nvram set fh_2g_band_flag=1
nvram set fh_5g_band_flag=2
nvram set bh_band_flag=2

nvram set fh_2g_ssid="$(nvram get ${intf2}_ssid)"
val="$(nvram get ${intf2}_akm)"
if [ -z "$val" ] || [ "$val" = "open" ]; then
	nvram set fh_2g_akm=psk2
	nvram set fh_2g_crypto=aes
	nvram set fh_2g_wpa_psk=12345678
else
	nvram set fh_2g_akm="$(nvram get ${intf2}_akm)"
	nvram set fh_2g_crypto="$(nvram get ${intf2}_crypto)"
	nvram set fh_2g_wpa_psk="$(nvram get ${intf2}_wpa_psk)"
fi

nvram set fh_5g_ssid="$(nvram get ${intf5}_ssid)"
val="$(nvram get ${intf5}_akm)"
val="$(nvram get ${intf5}_akm)"
if [ -z "$val" ] || [ "$val" = "open" ]; then
	nvram set fh_5g_akm=psk2
	nvram set fh_5g_crypto=aes
	nvram set fh_5g_wpa_psk=12345678
else
	nvram set fh_5g_akm="$(nvram get ${intf5}_akm)"
	nvram set fh_5g_crypto="$(nvram get ${intf5}_crypto)"
	nvram set fh_5g_wpa_psk="$(nvram get ${intf5}_wpa_psk)"
fi

nvram set bh_ssid="BackHaul_$(cat /proc/sys/kernel/random/uuid | md5sum |cut -c 1-4)"
nvram set bh_akm=psk2
nvram set bh_crypto=aes
nvram set bh_wpa_psk="$(cat /proc/sys/kernel/random/uuid | md5sum |cut -c 1-10)"
nvram set wps_custom_ifnames=${intf5}

#nvram commit
echo "@@@@@@@@@@@@@@@ mesh_role_master_wl_set.sh done @@@@@@@@@@@@@@@@@@@@@"