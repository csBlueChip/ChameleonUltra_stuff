#!/bin/bash

. cu-daemon.sh

# ----- edit to taste, or add a cli parser
#cuCli="ChameleonUltra/software/script/chameleon_cli_main.py"
cuCli="$1"
pc2cu="/tmp/cu_cu2pc"
cu2pc="/tmp/cu_pc2cu"
cutty="/dev/ttyACM0"

# ----- i like brevity
declare -n  CAP=CU_CAP

# ----- setup
Setup  "$pc2cu"  "$cu2pc"  "$cuCli"  ||  exit $?
Listen                         # wait for FIRST prompt
Show                           # show output

# ----- connect
n=0
q=""
while (( n == 0 )) ; do
	Send $q "hw connect -p ${cutty}"  # send connect command
	Listen -c -q
	[[ "${CAP[*]}" == *"Connect fail"* ]]  &&  sleep 1  ||  Status n
	q="-q"
done
Status n desc
echo -e "\e[1;37m# Status: $n:|$desc|\e[0m"

# ----- do some stuff surrounded by logic
spinr="-/|\\"
n=0
qs=""
ql="-q"
while true ; do
	echo -en "${spinr:n:1}"
	echo -en "\b"

	# press CR to toggle noisy/quiet mode
	if read -t 0 -n 1 line ; then
		[[ -z "$ql" ]] && ql="-q" || ql=""
		while read -t 0.1 -n 1 ; do : ; done
	fi

	Send $qs "hf mfu rdpg -p 0"
	Listen -c $ql  || exit $?
	data=${CAP[@]:0:2}  ;  data=${data##* }
	[[ -z $data ]] || echo -en "*"
	((n = (n+1) %4))
	qs="-q"
done
