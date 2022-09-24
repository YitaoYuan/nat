#!/bin/bash

set -e

switch="switch"
ucli_script=
bfrt_script=
switchd=$SDE/run_switchd.sh
bfshell=$SDE/run_bfshell.sh
count=
dmac_arr=
smac_arr=
port_arr=
nf_port=
server_type=
net_id=
LAN_net_addr=0xC0A800
WAN_net_addr=0xC0A802

get_server_mac() {
    if [ $# != 2 ]; then
	echo "usage: get_mac server_name iterface_name"
	exit 1
    fi
    server=$1
    interface=$2
    #echo -n "$server/$interface: "
    res=`ssh -o PasswordAuthentication=no -o StrictHostKeyChecking=no $server \
	"ifconfig | grep $interface -A 5 | grep ether | grep -E -o \"(.{2}:){5}.{2}\"; exit" \
	2>&1`
    if [ $? != 0 ]; then
        echo "failed"
    else
        echo "$res"
    fi
}

load_simple_l3() {
    $switchd -p simple_l3 > /dev/null 2>&1 &
}

kill_simple_l3() {
    PIDS=`ps aux | grep -E "[0-9]{2} bf_switchd.{10,}simple_l3" | sed "s/[^0-9]*\([0-9]*\).*/\1/g"`
    kill -9 $PIDS
}

get_mac_and_port(){
    if [ $# != 1 ]; then 
	echo "error"
	exit 1
    fi

    load_simple_l3

    port_mac_get=
    dev_port_get=
    local IFS=$'\n'

    count=($1)
    count=${#count[@]}
    echo "find $count entries"

    dmac_str=
    smac_str=
    port_str=
    nf_id=

    for line in $1
    do
	local IFS=$' \t'
	arr=($line)
	#echo ${#arr[@]}
	if [ ${#arr[@]} != 5 -a ${#arr[@]} != 6 ]; then # worker1 enp178s0f0 9 0 LAN 1
	    continue
	fi
	dmac_str="$dmac_str"`get_server_mac ${arr[0]} ${arr[1]}`$'\n'
	port_mac_get="${port_mac_get}port_mac_get ${arr[2]} ${arr[3]}"$'\n'
	dev_port_get="${dev_port_get}show -p ${arr[2]}/${arr[3]} -d"$'\n'
	if [ ${arr[4]} == "NF" ]; then
            nf_id=${#server_type[@]}
	    net_id=(${net_id[@]} 0)
	    #echo $nf_id
	else
	    net_id=(${net_id[@]} ${arr[5]})
        fi
	server_type=(${server_type[@]} ${arr[4]})
    done
    IFS=$' \t\n'
    
    ucli_script=$DIR/ucli_mac_get.py
    echo $'ucli\n..\n..\n..' > $ucli_script # bf_pltfm & chss_mgmt are not necessary
    echo -n "$port_mac_get" >> $ucli_script
    echo "pm" >> $ucli_script
    echo -n "$dev_port_get" >> $ucli_script
    echo '..' >> $ucli_script
    echo $'exit\nexit' >> $ucli_script

    #cat $ucli_mac_get_script
    res=`$bfshell -f $ucli_script`
    smac_str=`echo "$res" | grep -E "Port/channel:.+Port Mac addr:.+" | grep -o -E "(\w{2}:){5}\w{2}"`
    port_str=`echo "$res" | grep -E "[0-9]+ : Dev Port" | grep -o -E "[0-9]+"`
    kill_simple_l3

    #echo "$dmac_str" "$smac_str" "$port_str"
    dmac_arr=($dmac_str)
    smac_arr=($smac_str)
    port_arr=($port_str)
    nf_port=${port_arr[$nf_id]}
    if [ ${#dmac_arr[@]} != $count -o ${#smac_arr[@]} != $count -o ${#port_arr[@]} != $count -o ${#server_type[@]} != $count ]; then
	echo "some queries failed"
	exit 1
    fi
}

gen_bfrt_script() {
    bfrt_script=$DIR/bfrt_table_init.py
    echo -n "" > $bfrt_script
    for i in $(seq 0 `expr $count - 1`)
    do
	#set -x
	#echo $i
	echo "bfrt.nat.ParserI.PORT_METADATA.add(${port_arr[$i]}, $nf_port)" >> $bfrt_script
	if [ ${net_id[$i]} -gt 9 ]; then
	    echo "net id too big, you can modify this script to fit that number"
	    exit 1
	fi

	if [ "${server_type[i]}" == "LAN" ]; then
	    net_addr=${LAN_net_addr}0${net_id[$i]}
	elif [ "${server_type[i]}" == "WAN" ]; then
	    net_addr=${WAN_net_addr}0${net_id[$i]}
	fi

	if [ "${server_type[i]}" != "NF" ]; then
	    echo "bfrt.nat.IngressP.send_out.ip2port_mac.add_with_ipv4_forward($net_addr, 32, ${port_arr[$i]}, ${smac_arr[$i]}, ${dmac_arr[$i]})" >> $bfrt_script
	fi
    done
}

DIR=`cd $(dirname $0); pwd`
config=`cat $DIR/config | grep -o -E "\S+\s+\S+\s+[0-9]+\s+[0-9]+\s+(LAN\s+[0-9]+|WAN\s+[0-9]+|NF)" #"\S+\s+\d+\s+\d+\s+(LAN\s+\d+|WAN\s+\d+|NF)"`
get_mac_and_port "$config"
gen_bfrt_script
echo ${smac_arr[@]}
echo ${dmac_arr[@]}
echo ${port_arr[@]}
echo ${server_type[@]}
echo ${nf_port}
cat $bfrt_script
