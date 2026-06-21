#!/bin/sh
if [ $(nvram get tnt_debug)"A" == "1A" ]; then
	logger "TNT:debug host-down start!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	logger TNT:NETNAME=$NETNAME
	logger TNT:NAME=$NAME
	logger TNT:DEVICE=$DEVICE
	logger TNT:INTERFACE=$INTERFACE
	logger TNT:NODE=$NODE
	logger TNT:REMOTEADDRESS=$REMOTEADDRESS
	logger TNT:REMOTEPORT=$REMOTEPORT
	logger TNT:SUBNET=$SUBNET
	logger TNT:WEIGHT=$WEIGHT
	logger "TNT:debug host-down done!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
fi