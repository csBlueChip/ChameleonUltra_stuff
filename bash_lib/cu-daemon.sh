#==============================================================================
# API
#==============================================================================
# Setup the CU as a daemon
#
#   Setup [-f]  "pipe_pc2cu"  "pipe_cu2pc"  "/path/to/chameleon_cli_main.py"
#     -f     : force remove any existing pipes (should never be required)
#     pc2cu  : filespec for named pipe - for sending commands
#     cu2pc  : filespec for named pipe - for receiving responses
#
# Returns:
#       0    : [OK]
#     241    : Can not make F1FOs
#     242    : Did not make F1FOs
#     243    : Specified CLI does not exist
#     245    : CU did not start
#
# Exposes
#   CU_TX_NP : Transmit (PC-->CU) Named Pipe
#   CU_RX_NP : Receive  (PC<--CU) Named Pipe
#   CU_TX_FD : Transmit (PC-->CU) File Descriptor
#   CU_RX_FD : Receive  (PC<--CU) File Descriptor
#   CU_PID   : Background/Daemon process PID
#
Setup() {
	declare    force
	[[ "$1" == "-f" ]] && {
		force=1
		shift
	} || {
		force=0
	}

	declare -g CU_TX_NP="$1"
	declare -g CU_RX_NP="$2"
	declare    cli="$3"

	declare -g CU_PID
	declare -g CU_TX_FD  CU_RX_FD

	# Confiure the atexit() clean-up function
	trap  Cleanup  EXIT INT TERM  # $?, 130, 143

	# Force removal of existing named pipes (should never be required)
	(( !force ))  ||  rm -f --  "$CU_TX_NP"  "$CU_RX_NP"

	# Create new pipes - BOTH MUST be r/w
	mkfifo -m 600  "$CU_TX_NP"  "$CU_RX_NP"  ||  return 241  #  cannot makes F1fos

	[[ -p "$CU_TX_NP" ]] && [[ -p "$CU_RX_NP" ]]  ||  { return 242; }

	# Start CU as a background process, bound to the pipes
	[[ -f ${cli} ]] || {
		>&2  echo "Cannot find |${cli}|"
		return 243  # CU interface not found
	}

	"${cli}" --pipe  <"$CU_TX_NP"  >"$CU_RX_NP"  2>"$CU_RX_NP"  &
	CU_PID=$!                             # grab the PID
	sleep 1                               # give it a moment
	kill -0 "$CU_PID" 2>/dev/null  ||  {  # check if it started OK
		rm -f "$CU_TX_NP" "$CU_RX_NP"  # erase pipes
		unset  CU_TX_NP  CU_RX_NP      # ...
		unset  CU_PID                  # ...
		return 245                     # report error
	}

	# Associate pipes with file handles
	# ...this stops the pipes closing after each command
	exec {CU_TX_FD}<>"$CU_TX_NP"
	exec {CU_RX_FD}<>"$CU_RX_NP"

	return 0
}

#==============================================================================
# Clean-up. Called automatically when the script closes
#
Cleanup() {
	local  code=$?

	trap '' INT             # disable ^C
	trap - EXIT TERM        # stop trapping signals

	echo -e "\nCleanup..."

	# Kill the CU process
	if [[ -n "$CU_PID" ]] ; then
		kill "$CU_PID" 2>/dev/null  # send SIGTERM
		sleep 0.1                   # wait
		#    ...If it's still alive - send SIGKILL
		 ! kill -0 "$CU_PID" 2>/dev/null  ||  kill -9 "$CU_PID" 2>/dev/null
		# Wait for it to die
		wait "$CU_PID" 2>/dev/null
	fi

	# Close the file handles
	[[ -z "${CU_TX_FD:-}" ]]  ||  exec {CU_TX_FD}>&-
	[[ -z "${CU_RX_FD:-}" ]]  ||  exec {CU_RX_FD}<&-

	# Erase the named pipes
	rm -f --  "$CU_TX_NP"  "$CU_RX_NP"

	# 128 + {2:SIGINT=130, 15:SIGTERM=143} else `exit N`
	exit $code
}

#==============================================================================
# Send command to CU
#
# Syntax:
#   Send [-q] ["command string"|command string]  (quotes optional)
#     -q  : quiet (do NOT echo the command)
#
# Returns:
#     0   : [OK]
#   101   : CU has disappeared
#
# Notes:
#   The first thing Send does is drain the console to (effectively) /dev/null
#   So `Send this ; Send that ; Listen -c ` will only capture "that" reply
#
Send() {
	while read -r  -u "$CU_RX_FD"  -t 0.01 _ ; do : ; done  # drain the pipeline

	local  quiet
	[[ "$1" == "-q" ]] && {
		quiet=1
		shift
	} || {
		quiet=0
	}

	kill -0 "$CU_PID" 2>/dev/null || return 101  # process died

	(( quiet )) || {
		echo -en "\e[1;35m"  # 1=bright, 35=magenta ink
		echo -n  "$@"        # full command
		echo -e  "\e[0m"     # attribs off
	}

	# Send the command - use TX file handle, not TO pipe
#	printf "%s " "$@"  >&"$CU_TX_FD"
#	printf "\n"        >&"$CU_TX_FD"
	echo "$@"  >&"$CU_TX_FD"

	return 0
}

#==============================================================================
# Listen for response
#
# Syntax:
#   Listen [-q] [-c] [-s]
#     -q     : quiet   (do NOT echo to stdout)
#     -c     : capture (append data to CAP buffer)
#     -s     : status: include status+prompt line
#
# Returns:
#    0       : found command prompt [OK]
#   99       : CU said "<bye>"
#   70       : timeout
#
# Exposes:
#   CU_CAP[] : The capture buffer (as an array)
#
# Notes:
#   Timeout defaults to 2 seconds
#     override         with `CU_TMO=n` (seconds)
#     reset to default with `CU_TMO=` or `unset CU_TMO`
#
Listen() {
	declare     prompt="chameleon -->"
	declare     byemsg="Bye, thank you.  ^.^"
	declare -ga CU_CAP                  # global capture buffer

	declare     tmof=1                  # assume timeout occurs

	declare     quiet  capture  status  # arg flags
	declare     line  body  blank       # process

	# Handle arg flags
	[[ " $* " == *" -q "*  ]]  &&  quiet=1    ||  quiet=0
	[[ " $* " == *" -c "*  ]]  &&  capture=1  ||  capture=0
	[[ " $* " == *" -s "*  ]]  &&  status=1   ||  status=0

	# Default timeout is 2 seconds
	[[ -n ${CU_TMO} ]]  ||  CU_TMO=2   # set default timeout

	# Empty capture buffer
	CU_CAP=() 

	# Read to CAP, until termination event - use RX file handle, not FROM pipe
	body=0
	blank=()
	while  IFS=  read -r  -t "${CU_TMO}"  -u "$CU_RX_FD"  line ; do
		# Strip trailing line endings
		line="${line%"${line##*[!$'\r\n']}"}"     #"ignorethis

		# Ignore leading blank lines, and the initial command echo
		if (( !body )) ; then
			[[ -z "$line" ]]  ||  body=1
			continue
		fi

		# stdout output
		((  quiet   ))  ||  printf "%s%s%s\n" $'\e[0;32m' "$line" $'\e[0m'

		# Check termination conditions
		if [[ "$line" == "["*"$prompt"* ]] ; then
			(( !status ))  ||  CU_CAP+=("$line")
			tmof=0              # we did NOT timeout
			break
		fi
		if [[ "$line" == *"${byemsg}"*  ]] ; then
			return 99           # CU said "<bye>"
		fi

		# CAPture buffer append
		(( !capture ))  ||  CU_CAP+=("$line")

	done
	(( !tmof ))  ||  return 70  # TimeOut occurred

	while read -r  -t 0.001  -u "$CU_RX_FD" ; do : ; done  # drain the pipeline

	return 0
}

#==============================================================================
# Show capture buffer
#
# Syntax:
#   Show [-p[n]]
#     -p  : show 'enter next command' prompt
#     -pn : ...exclude trailing \n
#
# Returns:
#    0    : [OK]
#
Show() {
	printf "\e[0;33m"  # dim yellow
	printf "%s\n"  "${CU_CAP[@]:0:${#CU_CAP[@]}}"
	printf "\e[0m"     # reset colours

	return 0
}

#==============================================================================
Status() {
	[[ -n $1 ]]  &&  declare -n val=$1  ||  declare val
	[[ -n $2 ]]  &&  declare -n sts=$2  ||  declare sts

	Send -q $'\n'
	Listen -q -c -s

	sts="${CU_CAP[0]}"
	sts=`cut -d']' -f1 <<<"${sts#"${sts%%[! \[]*}"}"`
	CU_CAP=()

	if   [[ "$sts" == "Offline" ]] ; then  val=0
	elif [[ "$sts" == "USB"     ]] ; then  val=1
	else
		echo "! Unknown Status |$sts| ...examine and fix!"
		val=255
		return 1
	fi

	[[ -n $1 ]] || echo "Status: $val - $sts"

	return 0
}

#==============================================================================
[[ "${BASH_SOURCE[0]}" != "${0}" ]] || {
	echo "This is a library - you cannot run it"
	echo 'Include it in your BASh script with `. '$0'`'
	echo "The following functions become available"
	grep '^[A-Z]' "$0" | sed -E 's/^([^ ]*) .*/  - \1/'
	exit 1
}
