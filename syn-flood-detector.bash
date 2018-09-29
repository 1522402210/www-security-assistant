#!/bin/bash -e

# Name:    syn-flood-detector.sh
# Summary: Custom script that analyse the output of 'netstat' for THRESHOLD number of 'SYN_RECV' TCP states per IP/PORT, etc.
#          When possible SYN FLOOD attack is detected it calls www-security-assistant.bash from the same packages.
#          The script is designed to be run via CRON Job or as SHELL Command.
# Home:    https://github.com/pa4080/www-security-assistant
# Author:  Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2018
# Default: The default work directory is '/var/www-security-assistant' (see below).
#          If you are going to change this value, do it for the entire script bundle.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.
#
# The sctipt has two modes
# - Default mode, that will outut the result in CLI: '/var/www-security-assistant/syn-flood-detector.bash' or 'syn-flood-detector'
# - AutoMode, that should be used in Root`s Crontab: '* * * * * "/var/www-security-assistant/syn-flood-detector.bash" 'AutoMode' >> "/var/www-security-assistant/www-security-assistant.exec.log" 2>&1'

# The script should be run as root
[[ "$EUID" -ne 0 ]] && { echo "Please run as root (use sudo)."; exit 0; }

# The directory where the script is located - see the 'default' note in the beginning.
WORK_DIR="/var/www-security-assistant"
CONF_FILE="${WORK_DIR}/www-security-assistant.conf"

# EnVars
EXEC_LOG="${WORK_DIR}/www-security-assistant.exec.log"
MY_DIVIDER="$(grep '^MY_DIVIDER' "$CONF_FILE" | sed -r "s/^MY_DIVIDER='(-.*-)'.*$/\1/")"
TEMP_FILE="${WORK_DIR}/syn-flood-detector.tmp"
SEC_ASSISTANT="${WORK_DIR}/www-security-assistant.bash"

TCP_STATE='SYN_RECV'

# THRESHOLD
COMMON_SYN_THRESHOLD='120'
SINGLE_SYN_THRESHOLD='80'

# Main Scrip BEGIN
/bin/netstat -tnupa > "$TEMP_FILE"
COMMON_SYN_COUNT="$(grep -c 'SYN_RECV' "$TEMP_FILE" )"

if [[ $COMMON_SYN_COUNT -ge $COMMON_SYN_THRESHOLD  ]]
then
	#echo $COMMON_SYN_COUNT
	OUR_IPs=( $(grep "$TCP_STATE" "$TEMP_FILE" | awk '{print $4}' | cut -d':' -f1 | sort -u) )
	#echo $OUR_IPs
	for OUR_IP in "${OUR_IPs[@]}"
	do
		#echo $OUR_IP
		OUR_PORTs=( $(grep "$TCP_STATE" "$TEMP_FILE" | awk '{print $4}' | cut -d':' -f2 | sort -u) )
		#echo $OUR_PORTs
		for OUR_PORT in "${OUR_PORTs[@]}"
		do
			#echo $OUR_PORT
			ATTACKING_IPs=( $(grep "$TCP_STATE" "$TEMP_FILE" | grep "$OUR_IP" | grep "$OUR_PORT" | awk '{print $5}' | cut -d':' -f1 | sort -u) )
			#echo $ATTACKING_IPs
			for ATTACKING_IP in "${ATTACKING_IPs[@]}"
			do
				#echo $ATTACKING_IP
				SINGLE_SYN_COUNT="$(grep "$TCP_STATE" "$TEMP_FILE" | grep "$OUR_IP" | grep "$OUR_PORT" | grep -c "$ATTACKING_IP")"
				#echo $SINGLE_SYN_COUNT
				if [[ $SINGLE_SYN_COUNT -ge $SINGLE_SYN_THRESHOLD  ]]
				then
					if [[ ${1} == 'AutoMode' ]]
					then
						# Compose the log note
						ATTACK_INFO="Attacking IP: ${ATTACKING_IP}${MY_DIVIDER}${TCP_STATE} count: ${SINGLE_SYN_COUNT}${MY_DIVIDER}On our IP/Port: ${OUR_IP}/${OUR_PORT}"
						# Call WWW Security Assistant Script
						exec "$SEC_ASSISTANT" "$ATTACKING_IP" 'SynDetector' "$ATTACK_INFO" >> "$EXEC_LOG" 2>&1 &
					else
						printf '\n***\nSYN FLOOD attack detected:\nFrom attacking IP: \t%s\n%s count: \t%s\nOn our IP/Port: \t%s/%s\n' "$ATTACKING_IP" "$TCP_STATE" "$SINGLE_SYN_COUNT" "$OUR_IP" "$OUR_PORT"
					fi
				fi
			done
		done
	done
fi

exit 0