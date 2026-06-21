#!/bin/sh

#0axel -n $1 -T 5 $2>/var/speed_file
#curl -o /dev/null $2 2> /var/speed_file
#!/bin/bash

rm /var/speed_file 2>/dev/null
rm /var/speed_result 2>/dev/null

curl -m 8 -o /dev/null $2 2>/var/speed_file

buf=`cat /var/speed_file | grep with`
var=${buf##*with}
var=${var%%out*}

#echo $buf
#echo $var 
#echo $var>/var/speed_file
#echo $var>/var/speed_file
#cat /var/speed_file | cut -d ' ' -f 3

if [ -z "$var" ]; then 
    echo "STRING is empty"
	echo 0 >/var/speed_result
else
	echo $var >/var/speed_result
fi


#echo $rusult

