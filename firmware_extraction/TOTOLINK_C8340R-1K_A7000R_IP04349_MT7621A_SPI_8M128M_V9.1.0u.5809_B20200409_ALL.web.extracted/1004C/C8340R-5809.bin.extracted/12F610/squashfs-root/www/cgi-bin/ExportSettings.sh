#!/bin/sh

eval `/usr/sbin/nvram save /tmp/nv.cfg`
HARDWARE_MODEL=`nvram get model_custom`
dateStr=`date  '+%Y%m%d'`
filename=\"Config-$HARDWARE_MODEL-$dateStr.dat\"

echo "Pragma: no-cache\n"
echo "Cache-control: no-cache\n"
echo "Content-type: application/octet-stream"
echo "Content-Transfer-Encoding: binary"			#  "\n" make Un*x happy
echo "Content-Disposition: attachment; filename=$filename"
echo ""

cat /tmp/nv.cfg 2>/dev/null
rm -f  /tmp/nv.cfg

