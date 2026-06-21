#!/bin/sh

trap "" 2


case "$1" in
	start)
		echo "Loading drivers and kernel modules... "
		echo

# Syntax
# line
# conditon
# condition
# for
# -BUILD_FEATURE_A
# will
# -!BUILD_FEATURE_B
# will
 
# bcmlibs
insmod /lib/modules/4.1.52/extra/bcmlibs.ko  
 
# UBUS
 
 
#I2C 
 
# PON
 
# BPM
 
# VLAN
insmod /lib/modules/4.1.52/extra/bcmvlan.ko  
 
# RDPA
 
# RDPA_User
 
 
# General
insmod /lib/modules/4.1.52/extra/chipinfo.ko  
 
# Ingress
# Must
insmod /lib/modules/4.1.52/extra/bcm_ingqos.ko  
 
# RDPA
 
insmod /lib/modules/4.1.52/extra/pktflow.ko  
insmod /lib/modules/4.1.52/extra/cmdlist.ko  
insmod /lib/modules/4.1.52/extra/archer.ko  
 
# enet
 
 
insmod /lib/modules/4.1.52/extra/bcm_enet.ko  
# moving
insmod /lib/modules/4.1.52/extra/bcmmcast.ko  
 
# EAPFWD:
 
#load SATA/AHCI
 
# PCIe
insmod /lib/modules/4.1.52/extra/bcm_pcie_hcd.ko  
 
# pcie
 
# WLAN
 
# NetXL
 
#Voice 
 
 
#load usb
 
# other
 
insmod /lib/modules/4.1.52/extra/pwrmngtd.ko  
 
insmod /lib/modules/4.1.52/extra/bcm_thermal.ko  
 
# presecure
insmod /lib/modules/4.1.52/extra/otp.ko  
 
# LTE
 

 test -e /etc/rdpa_init.sh && /etc/rdpa_init.sh

# Enable the PKA driver.
 test -e /sys/devices/platform/bcm_pka/enable && echo 1 > /sys/devices/platform/bcm_pka/enable

exit 0
		;;

	stop)
		echo "removing bcm base drivers not implemented yet..."
		exit 1
		;;

	*)
		echo "bcmbasedrivers: unrecognized option $1"
		exit 1
		;;

esac


