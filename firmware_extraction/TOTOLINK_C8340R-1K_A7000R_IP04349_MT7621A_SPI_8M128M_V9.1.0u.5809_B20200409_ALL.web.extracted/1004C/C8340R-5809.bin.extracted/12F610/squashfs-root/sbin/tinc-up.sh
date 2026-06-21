#!/bin/sh
if [ $(nvram get tnt_debug)"A" == "1A" ]; then
	logger "TNT:debug tinc-up start**********************************"
	logger TNT:NETNAME=$NETNAME
	logger TNT:NAME=$NAME
	logger TNT:DEVICE=$DEVICE
	logger TNT:INTERFACE=$INTERFACE
	logger TNT:NODE=$NODE
	logger TNT:REMOTEADDRESS=$REMOTEADDRESS
	logger TNT:REMOTEPORT=$REMOTEPORT
	logger TNT:SUBNET=$SUBNET
	logger TNT:WEIGHT=$WEIGHT
	logger "TNT:debug tinc-up done***********************************"
fi
iptables -t mangle -D TNT_IP_RULE -j MARK --set-mark 0x1/0xf;
ip route del default dev $INTERFACE tab 10;
ip rule del fwmark 0x1/0xf pref 10 table 10;
ip rule add fwmark 0x1/0xf pref 10 table 10;
if [ $(nvram get tnt_default_route)"A" != "0.0.0.0A" ]; then
iptables -t mangle -A TNT_IP_RULE -j MARK --set-mark 0x1/0xf;
ip route add default via $(nvram get tnt_default_route) dev $INTERFACE tab 10;
fi