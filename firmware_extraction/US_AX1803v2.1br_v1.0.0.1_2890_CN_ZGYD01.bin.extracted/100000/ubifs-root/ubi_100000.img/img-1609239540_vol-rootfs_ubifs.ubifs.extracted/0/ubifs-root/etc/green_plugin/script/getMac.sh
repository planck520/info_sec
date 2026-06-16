#不同的型号使用对应的脚本获取Mac，写入文件
#S21g-01
#ifconfig en0|grep en0|awk '{print $5}' > /var/deviceMac.txt
#H10g-02
#ifconfig en0|grep en0|awk '{print $5}' > /var/deviceMac.txt
#SVG6000RW-M
#cat /sys/class/net/br0/address  > /var/deviceMac.txt
#echo "" > /var/deviceMac.txt && cat /sys/class/net/br0/address  > /var/deviceMac.txt && echo "" >>  /var/deviceMac.txt
echo "" > /tmp/deviceMac.txt && ifconfig |grep br-lan|awk '{print $5}' > /tmp/deviceMac.txt && echo "" >> /tmp/deviceMac.txt
echo "" > /tmp/wanMac.txt && ifconfig |grep eth1|awk '{print $5}' > /tmp/wanMac.txt && echo "" >> /tmp/wanMac.txt
