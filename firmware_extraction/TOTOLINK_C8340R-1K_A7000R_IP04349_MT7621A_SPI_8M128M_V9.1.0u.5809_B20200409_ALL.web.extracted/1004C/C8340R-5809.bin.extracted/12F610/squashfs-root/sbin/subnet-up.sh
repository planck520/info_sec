#!/bin/sh
if [ $(nvram get tnt_debug)"A" == "1A" ]; then
	logger "TNT:debug subnet-up start................................"
	logger TNT:NETNAME=$NETNAME
	logger TNT:NAME=$NAME
	logger TNT:DEVICE=$DEVICE
	logger TNT:INTERFACE=$INTERFACE
	logger TNT:NODE=$NODE
	logger TNT:REMOTEADDRESS=$REMOTEADDRESS
	logger TNT:REMOTEPORT=$REMOTEPORT
	logger TNT:SUBNET=$SUBNET
	logger TNT:WEIGHT=$WEIGHT
	logger "TNT:debug subnet-up done................................."
fi
if [ $(nvram get tnt_declare_accept)"A" == "0A" ]; then
exit 0;
fi
num=$(echo $NODE | grep -c "$(nvram get tnt_net_id)");
if [ $num -eq 0 ]; then
logger 000000000000;
exit 0;
fi
num=$(echo $NODE | grep -c "$(nvram get tnt_dev_id)");
if [ $num -eq 1 ]; then
logger 1111111111111;
exit 0;
fi
num=$(echo $SUBNET | grep -c "/");
if [ $num -eq 0 ]; then
logger 2222222222222;
exit 0;
fi
node_dev_id=$(echo $NODE|head -c 26|tail -c 16);
node_my_ip=$(cat /var/run/tnt.edge_list |grep $node_dev_id|cut -d" " -f6);
logger node_dev_id=$node_dev_id;
logger node_my_ip=$node_my_ip;
ip route re $SUBNET via $node_my_ip dev $INTERFACE tab 10;
iptables -t mangle -D TNT_IP_RULE -d $SUBNET -j MARK --set-mark 0x1/0xf;
iptables -t mangle -A TNT_IP_RULE -d $SUBNET -j MARK --set-mark 0x1/0xf;