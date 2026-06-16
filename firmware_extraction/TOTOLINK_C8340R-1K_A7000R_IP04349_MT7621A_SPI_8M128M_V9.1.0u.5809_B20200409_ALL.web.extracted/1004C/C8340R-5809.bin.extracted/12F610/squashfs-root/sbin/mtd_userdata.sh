#!/bin/sh

result=0
mtd_part_name="Userdata"
mtd_part_dev="/dev/mtdblock5"
mtd_part_size=65536
dir_userdata="/etc/userdata"
slk="/tmp/.userdata_locked"
tmp="/tmp/userdata.tar"
tbz="${tmp}.bz2"
hsh="/tmp/hashes/userdata_md5"

func_get_mtd()
{
	local mtd_part mtd_char mtd_idx mtd_hex
	mtd_part=`cat /proc/mtd | grep \"$mtd_part_name\"`
	mtd_char=`echo $mtd_part | cut -d':' -f1`
	mtd_hex=`echo $mtd_part | cut -d' ' -f2`
	mtd_idx=`echo $mtd_char | cut -c4-5`
	if [ -n "$mtd_idx" ] && [ $mtd_idx -ge 5 ] ; then
		mtd_part_dev="/dev/mtdblock${mtd_idx}"
		mtd_part_size=`echo $((0x$mtd_hex))`
	else
		logger -t "Userdata" "Cannot find MTD partition: $mtd_part_name"
		exit 1
	fi
}

func_mdir()
{
	[ ! -d "$dir_userdata" ] && mkdir -p -m 755 $dir_userdata
}

func_load()
{
	local fsz

	bzcat $mtd_part_dev > $tmp 2>/dev/null
	fsz=`stat -c %s $tmp 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -gt 0 ] ; then
		md5sum $tmp > $hsh
		tar xf $tmp -C $dir_userdata 2>/dev/null
	else
		result=1
		rm -f $hsh
		logger -t "User load" "Invalid user data in MTD partition: $mtd_part_dev"
	fi
	rm -f $tmp
	rm -f $slk
}

func_tarb()
{
	rm -f $tmp
	cd $dir_userdata
	find * -print0 | xargs -0 touch -c -h -t 201001010000.00
	find * ! -type d -print0 | sort -z | xargs -0 tar -cf $tmp 2>/dev/null
	cd - >>/dev/null
	if [ ! -f "$tmp" ] ; then
		logger -t "User" "Cannot create tarball file: $tmp"
		exit 1
	fi
}

func_save()
{
	local fsz

	#echo "Save Userdata files to MTD partition \"$mtd_part_dev\""
	rm -f $tbz
	md5sum -c -s $hsh 2>/dev/null
	if [ $? -eq 0 ] ; then
		#echo "Userdata hash is not changed, skip write to MTD partition. Exit."
		rm -f $tmp
		return 0
	fi
	md5sum $tmp > $hsh
	bzip2 -9 $tmp 2>/dev/null
	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -ge 16 ] && [ $fsz -le $mtd_part_size ] ; then
		mtd_write write $tbz $mtd_part_name 2>/dev/null
		if [ $? -eq 0 ] ; then
			result=0
		else
			result=1
			#echo "Error! MTD write FAILED"
			logger -t "User save" "Error write to MTD partition: $mtd_part_dev"
		fi
	else
		result=1
		#echo "Error! Invalid storage final data size: $fsz"
		logger -t "User save" "Invalid storage final data size: $fsz"
	fi
	rm -f $tmp
	rm -f $tbz
}

func_erase()
{
	mtd_write erase $mtd_part_name 2>/dev/null
	if [ $? -eq 0 ] ; then
		rm -f $hsh
		rm -rf $dir_userdata
		mkdir -p -m 755 $dir_userdata
		touch "$slk"
	else
		result=1
	fi
}


case "$1" in
load)
	func_get_mtd
	func_mdir
	func_load
	;;
save)
	[ -f "$slk" ] && exit 1
	func_get_mtd
	func_mdir
	func_tarb
	func_save
	;;
erase)
	func_get_mtd
	func_erase
	;;
*)
	echo "Usage: $0 {load|save|erase}"
	exit 1
	;;
esac

exit $result
