#!/bin/bash

. cu-daemon.sh

ESC=$'\e'
cBWHT="${ESC}[1;37m"
cNORM="${ESC}[0m"

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
	[[ "${CAP[0]}" == *"Connect fail"* ]]  &&  sleep 1  ||  Status n
	q="-q"
done
Status n desc
echo "${cBWHT}# Status: $n:|$desc|${cNORM}"

# ----- do a thing
Send "help"     || exit $?     # send "help" (shown next to prompt)
Listen -q -c    || exit $?     # -quiet (noecho) -capture (to $CAP[])
Show                           # show captured output

# ----- do some stuff surrounded by logic
q=""
while true ; do
	Send $q "hf mfu rdpg -p 2"
	Listen -c -q  || exit $?     # -capture (to $CAP[])
	data=${CAP[@]:0:2}  ;  data=${data##* }
	[[ -z $data ]] || break
	q="-q"
done

echo -en "${cBWHT}# Page 2: $data"
cnt=0 ; [[ ${data:2:2} == "48" ]] && cnt=135 || cnt=238
((cnt)) || exit 135
echo " - Read $cnt pages${cNORM}"

#=======================================================================================================================
# ----- incomplete read logic
#	[USB] chameleon --> hf mfu rdpg -p 120                 ; read page
#	 - Data: 0e3e80de                                      ;   OK
#	[USB] chameleon --> hf mfu rdpg -p 235                 ; read non-existent page
#	 - Data:                                               ;   no-data
#
#	[USB] chameleon --> hf mfu rdpg -p 120 -k cb19ac34     ; read page with GOOD password
#	 - PACK: 8080                                          ;   password ack
#	 - Data: 0e3e80de                                      ;   OK
#	[USB] chameleon --> hf mfu rdpg -p 120 -k cb19ac3F     ; read page with BAD password
#	 - Auth failed                                         ;   FAIL

#==============================================================================
# Read all the pages
#
tag=""
echo -n "|["
for ((i = 0;  i < cnt;  i++)) ; do       # loop
	Send -q "hf mfu rdpg -p $i"          #   send read-page
	Listen -q -c                         #   get reply
	[[ ${CAP[0]} == *"Data"* ]] && {     #   we have "Data"
		data=${CAP[0]##* }               #     extract the hex-data
		[[ -z $data ]] && {              #     did we get <blank>
			(( i==235 || i==236 )) && {  #       we expect nothing on these 2 pages
				data="5caff01d"          #         inject some scaffolding
			} || {                       #       we expect data on all other pages
				i=$((--i))               #         decrement page counter
				continue                 #         and go to the next page (ie. this page)
			}                            #       .
		}                                #     .
		tag="${tag}${data}"              #     add the data to the tag string
		echo -n "${data}|"               #     friendly output for user
	}                                    #   .
done                                     # end.loop
echo -e "\b]|"

#==============================================================================
#==============================================================================
#==============================================================================

# ----- read data from tag
Peek() {  ## Peek  <page>,<offset>:<numberOfBytes> ...
	local out=""
	while [[ -n $1 ]] ; do
		local pg="${1%%,*}"
		local off="${1%%:*}" ; off="${off##*,}"
		local sz="${1##*:}"  ; sz=$((sz *2))
		local idx=$(( (pg *8) + (off *2) ))
		out="${out}${tag:${idx}:${sz}}"
		shift
	done
	echo -n "$out"
}

# ----- write data to tag
Poke() {  ## Poke <page>,<offset>=<hexstring>
	while [[ -n $1 ]] ; do
		local pg="${1%%,*}"
		local off="${1%%=*}" ; off="${off##*,}"
		local val="${1##*=}"
		local idx=$(( (pg *8) + (off *2) ))
		local next=$(( idx + ${#val} ))
		tag="${tag:0:${idx}}${val}${tag:${next}}"
		shift
	done
}

# ----- calculate password
Uid2Pwd() {
	declare -l  uid=$1   # 7-byte/14-character hex string

	declare -n  _pwd=$2   # result variable -> "xxxxxxxx"[8]
	declare -n  _pack=$3  # result variable -> "8080"[4]

	printf -v _pwd "%02x" \
		$(( 0xAA ^ 16#${uid:$((1*2)):2} ^ 16#${uid:$((3*2)):2} )) \
		$(( 0x55 ^ 16#${uid:$((2*2)):2} ^ 16#${uid:$((4*2)):2} )) \
		$(( 0xAA ^ 16#${uid:$((3*2)):2} ^ 16#${uid:$((5*2)):2} )) \
		$(( 0x55 ^ 16#${uid:$((4*2)):2} ^ 16#${uid:$((6*2)):2} ))
	#                          ^--- UID byte index ---^

	# The Password-ACK (sent BY the tag TO the reader, when it receives the right password)
	# ...is, for all Amiibo's, fixed as "8080"
	_pack="8080"

	return 0
}

#==============================================================================

# read the UID from the tag, using the correct method
INTSAK=`Peek  2,1:1`
[[ $INTSAK == "48" ]] && {
	tuid=`Peek  0,0:3  1,0:4`
} || {
	tuid=`Peek  0,0:4  1,0:3`
}

# calculate the tag password
Uid2Pwd "$tuid" pwd pack

# write it to the dump
Poke  133,0=$pwd       # password
Poke  134,0=$pack      # pack

# sanity readback
myVar=`Peek 133,0:6`
echo "# readback: $myVar"

# try and use the password
Send "hf mfu rdpg -p 133 -k $pwd"
Listen -c
[[ "${CAP[*]}" == *"PACK: ${pack}"* ]] && {
	echo "password verified"
} || {
	echo "password failed"
}

#==============================================================================
# ----- print and save the result
#
printf "\n---\n%s\n---\n"  $tag
xxx="`sed -E 's/(..)/\1 /g' <<<$tag`"
printf "%s %s %s %s | "  $xxx
xxd -p -r <<<$xxx >xtest.bin

#==============================================================================
# ----- cleanup is automatic
#
exit 0
