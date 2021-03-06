#!/bin/bash -e

# Name:    www-security-assistant.bash - this is the main scrypt of the script bundle WWWSecurityAssistant.
# Summary: Custom script designed to help you with malicious IP addresses handling.
#          The IPs should be provided by external programs such as ModSecurity or ModEvasive for Apache2.
# Home:    https://github.com/pa4080/www-security-assistant
# Author:  Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2018
# Default: The default work directory is '/var/www-security-assistant' (see below).
#          If you are going to change this value, do it for the entire script bundle.
#          Unfortunatelly WORK_DIR="$(dirname ${0})" - makes problems when we use `ln -s ...`
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.

# The script should be run as root
[[ "$EUID" -ne 0 ]] && { echo "Please run as root (use sudo)."; exit 0; }

# Check the dependencies
[[ -x /usr/bin/at ]] || { echo "Please, install 'at'"; exit 0; }
[[ -x /usr/bin/tee ]] || { echo "Please, install 'tee'"; exit 0; }
[[ -x /usr/bin/awk ]] || { echo "Please, install 'awk'"; exit 0; }
[[ -x /usr/bin/who ]] || { echo "Please, install 'who'"; exit 0; }
[[ -x /usr/bin/mail ]] || { echo "Please, install 'mail' command"; exit 0; }
[[ -x /sbin/iptables ]] || { echo "Please, install 'iptables'"; exit 0; }

# Check the input data
[[ -z ${1+x} ]] || [[ -z ${2+x} ]] && (echo "$USAGE"; echo; exit 0)

# Get the time coordinates of the event
TIME="$(date +%H:%M:%S)"
DATE="$(date +%Y-%m-%d)"

# Asign the input data to certain variables
IP="${1}"     # IP address - the first argument
AGENT="${2}"  # MODE or AGENT; Automatic MODE, available agents: [ ModSecurity | ModEvasive | Guardian | a2Analyst | SynDetector ]; Only ModSecurity and SynDetector use $NOTES
NOTES="${3}"  #                Manual MODE:                      [ --DROP "$NOTES" | --DROP-CLEAR "$NOTES" | --ACCEPT "$NOTES" | --ACCEPT-CHAIN "$NOTES" ]

# Get the $USER that execute the script
RUN_USER="$(who -m | awk '{print $1}')"
if [[ -z ${RUN_USER} ]]; then RUN_USER="${SUDO_USER:-${USER}}"; fi
if [[ -z ${RUN_USER} ]]; then RUN_USER="$USER"; fi
if [[ -z ${RUN_USER} ]]; then RUN_USER="root"; fi

## Read the configuration file and set few more configuration variables

# The directory where the script is located - see the 'default' note in the beginning.
WORK_DIR="/var/www-security-assistant"
CONF_FILE="${WORK_DIR}/www-security-assistant.conf"

# Load/source the configuration file
if [[ -f $CONF_FILE ]]
then
    source "${CONF_FILE}"
else
    echo "Please use \"${CONF_FILE}.example\" and create your own \"${CONF_FILE}\""
    exit 0
fi

# Touch some files with attention to create them in case they do not exist
touch "$HISTORY" "$WHITE_LIST" "$BAN_LIST" "$BAN_CLEAR_LIST"

## Output a header for the log file
printf "\n\n***** SECURITY LOG from %s on %s : www-security-assistant.bash : %s : %s\n\n" "$TIME" "$DATE" "$AGENT" "$IP"

## The ACTION SECTION

# If the $IP is a member of the $WHITE_LIST (grep -q "$IP" "$WHITE_LIST" - doesn't work)
if [[ ! -z $(grep -o "$IP" "$WHITE_LIST") ]]
then
    # Output a message and exit
    printf 'The IP address %s is a member of the Withe List!\n\n' "$IP"
    exit 0

# Add $IP to the DROP (BAN) List, syntax: www-security-assistant.bash <IP> --DROP 'log notes'"
elif [[ $AGENT == "--DROP" ]]
then
    /sbin/iptables -A GUARDIAN -s "$IP" -j DROP
    /sbin/iptables -L GUARDIAN -n --line-numbers
    eval "$IPTABLES_SAVE"
    # Output and Log a message and exit
    printf 'On %-10s at %-8s | This IP/CIDR was added to the DROP (BAN) List by @%s: %-18s \t| Notes: %s\n' "$DATE" "$TIME" "$RUN_USER" "$IP" "$NOTES" | tee -a "$BAN_LIST"
    exit 0

# Remove $IP from the DROP (BAN) List, syntax: www-security-assistant.bash <IP> --DROP-CLEAR 'log notes'"
elif [[ $AGENT == "--DROP-CLEAR" ]]
then
    /sbin/iptables -L GUARDIAN -n --line-numbers; echo
    /sbin/iptables -L SYN_FLOOD -n --line-numbers; echo
    sed -i "/$IP/d" "$HISTORY"
    sed -i "/$IP/d" "$BAN_LIST"
    echo 'Attemt to remove a rule from GUARDIAN or fron SYN_FLOOD chain:'
    /sbin/iptables -C GUARDIAN -s "$IP" -j DROP && /sbin/iptables -D GUARDIAN -s "$IP" -j DROP && echo 'The rule is removed from GUARDIAN.'
    /sbin/iptables -C SYN_FLOOD -s "$IP" -j DROP && /sbin/iptables -D SYN_FLOOD -s "$IP" -j DROP  && echo 'The rule is removed from SYN_FLOOD.'
    eval "$IPTABLES_SAVE"; echo
    /sbin/iptables -L GUARDIAN -n --line-numbers; echo
    /sbin/iptables -L SYN_FLOOD -n --line-numbers; echo
    # Output and Log a message and exit
    printf 'On %-10s at %-8s | This IP/CIDR was removed from the DROP (BAN) List by @%s: %-18s \t| Notes: %s\n' "$DATE" "$TIME" "$RUN_USER" "$IP" "$NOTES" | tee -a "$BAN_CLEAR_LIST"
    exit 0

# Add $IP to the ACCEPT (WHITE) List, syntax: www-security-assistant.bash <IP> --ACCEPT 'log notes'"
elif [[ $AGENT == "--ACCEPT" ]]
then
    # Output and Log a message and exit
    printf 'On %-10s at %-8s | This IP/CIDR was added to the ACCEPT (WHITE) List by @%s: %-18s \t| Notes: %s\n' "$DATE" "$TIME" "$RUN_USER" "$IP" "$NOTES" | tee -a "$WHITE_LIST"
    exit 0

# Add $IP to the ACCEPT (WHITE) List and add Iptables rule, syntax: www-security-assistant.bash <IP> --ACCEPT-CHAIN 'log notes'"
elif [[ "$AGENT" == "--ACCEPT-CHAIN" ]]
then
    /sbin/iptables -A GUARDIAN -s "$IP" -j ACCEPT
    /sbin/iptables -L GUARDIAN -n --line-numbers
    eval "$IPTABLES_SAVE"
    # Output and Log a message and exit
    NOTE='Iptables rule has been created!'
    printf 'On %-10s at %-8s | This IP/CIDR was added to the ACCEPT (WHITE) List by @%s: %-18s \t| Notes: %s %s\n' "$DATE" "$TIME" "$RUN_USER" "$IP" "$NOTES" "$NOTE" | tee -a "$WHITE_LIST"
    exit 0

# If the $AGENT belogs to the list of $AGENTS
elif [[ " ${AGENTS[@]} " == *" ${AGENT} "* ]]; then
    # Get the number of the previous transgressions from this $IP and increment +1 to get the current number;
    # Note '$(grep -c $IP $HISTORY)' sometimes works sometime doesn`t work '!!!'
    IP_SINS=$(cat "$HISTORY" | grep "$IP" | wc -l); IP_SINS=$((IP_SINS+1))

    if [[ ${AGENT} == "SynDetector" ]]
    then
        CHAIN='SYN_FLOOD'
    else
        CHAIN='GUARDIAN'
    fi

    if [[ $IP_SINS -le $LIMIT ]]
    then
        # Add the following firewall rule (block IP); alt.: `iptables -I INPUT -p tcp --dport 80 -s %s -j DROP`
        /sbin/iptables -I "$CHAIN" -s "$IP" -j DROP
        # Unblock offending IP after $BAN_TIME through the `at` command
        echo "/sbin/iptables -D \"$CHAIN\" -w -s \"$IP\" -j DROP && $IPTABLES_SAVE" | at now + "$BAN_TIME"
        # GO FORWARD
    else
        # Add $IP to the Black List add Iptales rule. Please note that
        # The $NOTES are not logged here, this will be done within the following section: Log the current thread
        /sbin/iptables -A "$CHAIN" -s "$IP" -j DROP
        eval "$IPTABLES_SAVE"
        printf 'On %-10s at %-8s | This IP/CIDR was added to the DROP (BAN) List by @%s: %-18s\n' "$DATE" "$TIME" "$AGENT" "$IP" | tee -a "$BAN_LIST"
        # GO FORWARD
    fi

# For all other cases
else
    echo "Something went wrong!"; echo; echo "$USAGE"; echo;
    exit 0
fi


## Prepare the notes that comes from modsecurity-assistant.sh
## The custom divider is used to dicourage some bug when the note comes from ModSecurity
NOTES_LOCAL="$(echo "$NOTES" | sed -e "s/$MY_DIVIDER/; /g")"
NOTES_EMAIL="$(echo "$NOTES" | sed -e "s/$MY_DIVIDER/\n/g")"

## Log the current thread into the $HISTORY file
printf 'On %-10s at %-8s | %-12s : %-18s | Notes: %s\n' "$DATE" "$TIME" "$AGENT" "$IP" "$NOTES_LOCAL" | tee -a "$HISTORY"

## The Construct E-MAIL SECTION

{
    printf '\n---===| %s Security Assistant |===---\n' "${HOSTNAME^^}"
    printf '\n%s:\n' "$AGENT"
if [[ $AGENT == "ModSecurity" ]]
then
    printf '\nNew transgression has been detected from this source IP address: %s\n\n' "$IP"
    echo "${NOTES_EMAIL}"
elif [[ $AGENT == "SynDetector" ]]
then
    printf '\nSYN FLOOD attack has been detected from this source IP address: %s\n\n' "$IP"
    echo "${NOTES_EMAIL}"
else
    printf '\nMassive connections has been detected from this source IP address: %s\n' "$IP"
fi
    printf '\nThe current number of committed transgressions from this IP is %s.\n' "$IP_SINS"
if [[ ! $IP_SINS -ge $LIMIT ]]
then
    printf '\nThe system has blocked the IP in the firewall for %s as from %s on %s.\n' "$BAN_TIME" "$TIME" "$DATE"
else
    printf '\nThey reached our Limit of tolerance, currently equal to %s transgressions, and were added to the BAN List on %s at %s!\n' "$LIMIT" "$DATE" "$TIME"
    printf '\n<!-- WHOIS %s report begin:\n\n' "$IP"; whois "$IP"; printf '\nWHOIS %s report end. -->\n' "$IP"
fi
    UNBLOCK="\n\t sudo iptables -D $CHAIN -s $IP -j DROP \n\t sudo www-security-assistant.bash $IP --DROP-CLEAR 'log notes'\n"
    printf '\nTo allow access to this IP address manually: %b' "$UNBLOCK"
if [[ $AGENT == "ModSecurity" ]]
then
    UNBLOCK="\n\t sudo modsec_white-list-rule-generator '999999' 'unique-id' '$(echo "$NOTES_EMAIL" | sed -r -n 's/^Unique ID: (.*)$/\1/p')'\n"
    printf '\nTo whitelist similar actions execute: %b' "$UNBLOCK"
    UNBLOCK="\n\t sudo www-security-assistant.bash $IP --DROP-CLEAR 'log notes' && sudo modsec_white-list-rule-generator '999999' 'unique-id' '$(echo "$NOTES_EMAIL" | sed -r -n 's/^Unique ID: (.*)$/\1/p')'\n"
    printf '\nTo perform booth whitelist similar actions and allow access to this IP address execute: %b' "$UNBLOCK"
fi
    printf '\n---===| %s Security Assistant |===---\n' "${HOSTNAME^^}"
} > "$EMAIL_BODY"


# Send the E-MAIL
mail -r "$EMAIL_FROM" -s "Attack Detected - ${HOSTNAME^^}" "$EMAIL_TO" < "$EMAIL_BODY"

# Remove ModEvasive lock file for future checks
if [[ $AGENT == 'ModEvasive' ]]; then rm -f "$EVASIVE_LOG/dos-$IP"; fi

# Add clarification to the copy of the last sent email
printf '\n***\n This email has been sent to %s at %s\n\n' "$EMAIL_TO" "$TIME" >> "$EMAIL_BODY"

exit 0