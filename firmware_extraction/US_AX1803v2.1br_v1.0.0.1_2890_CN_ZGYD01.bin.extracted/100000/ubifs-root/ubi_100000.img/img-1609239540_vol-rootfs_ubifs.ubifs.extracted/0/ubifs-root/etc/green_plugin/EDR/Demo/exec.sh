#! /bin/sh

COMMON_LIB_DIR=../Library
OPENSSL_DIR=/lib
APP_LIB_DIR=./library

export LD_LIBRARY_PATH=${COMMON_LIB_DIR}/mqtt/ax1803/lib:${APP_LIB_DIR}/edr:${OPENSSL_DIR}:$LD_LIBRARY_PATH
chmod u+x ./hiot_EDR
./hiot_EDR $*
