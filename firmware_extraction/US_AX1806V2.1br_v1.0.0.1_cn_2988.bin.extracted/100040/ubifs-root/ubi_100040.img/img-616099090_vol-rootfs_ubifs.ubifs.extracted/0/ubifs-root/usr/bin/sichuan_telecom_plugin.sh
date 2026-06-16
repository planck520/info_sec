#!/bin/sh
src_path="/usr/bin/"
dst_path="/ctcap/telecom/"
exe="Plugin"
start_shell="telecom_plugin_server_check"
config_file="plug.conf"
dev_report="telecom_dev_report"

if [ ! -x "$dst_path" ]; then
	mkdir "$dst_path"
fi

if [ ! -f "$dst_path$exe" ]; then
	cp -f $src_path$exe $dst_path$exe
fi

if [ ! -f "$dst_path$start_shell" ]; then
	cp -f $src_path$start_shell $dst_path$start_shell
fi

if [ ! -f "$dst_path$config_file" ]; then
	cp -f $src_path$config_file $dst_path$config_file
fi

if [ ! -f "$dst_path$dev_report" ]; then
	cp -f $src_path$dev_report $dst_path$dev_report
fi

chmod 777 -R $dst_path
$dst_path$start_shell &
$dst_path$dev_report &
