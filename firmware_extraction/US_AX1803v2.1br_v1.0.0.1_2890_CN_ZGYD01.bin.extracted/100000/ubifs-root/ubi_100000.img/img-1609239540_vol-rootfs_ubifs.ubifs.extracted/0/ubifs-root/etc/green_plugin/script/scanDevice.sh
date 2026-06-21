cat /proc/net/arp | grep "br-lan" | awk '{print $1 " " $3 " " $4}' | awk '!a[$2]++ || !a[$3]++' > /tmp/arpout.txt
