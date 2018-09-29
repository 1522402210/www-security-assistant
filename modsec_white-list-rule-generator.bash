#!/bin/bash

# $1 - The new Rule Number ID
# $2 - Type of the analysis: `latest-log` or `unique-id`
# $3 - The Unique ID of the log record (action)
# $4 - Default Method: `request`; The methods are not available at the moment: `cookie` `request cookie`; This variable is not manatory at the moment

# The script should be run as root
[[ "$EUID" -ne 0 ]] && { echo "Please run as root (use sudo)."; exit 0; }

LOG_FILE="/tmp/modsec_audit_cat.log"; cat "/var/log/apache2_mod_security/modsec_audit.log"{.1,} > "$LOG_FILE"
TMP_FILE="/tmp/modsec_rule_generator.tmp"

# Output colors
RED='\033[0;31m'
GRE='\033[0;32m'
YEL='\033[1;33m'
NCL='\033[0m'   # No color

get_info() {
	REMOTE_IP="$(sed -n -r 's/^\[.*\] .{28}([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) [0-9]+ .*$/\1/p' "$TMP_FILE")"
	LOCAL_HOST="$(sed -r -n 's/^Host: (.*)$/\1/p' "$TMP_FILE")"
	REQUEST_FULL="$(sed -r -n 's/^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS) (.*) (HTTP.*)$/\1 \2 \3/p' "$TMP_FILE")"
	ORIGIN_URL="$(sed -r -n 's/^Origin: (http.*)$/\1/p' "$TMP_FILE")"
	REFERER_URL="$(sed -r -n 's/^Referer: (http.*)$/\1/p' "$TMP_FILE")"

	REQUEST_URI="$(sed -r -n 's/^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS) (.*) (HTTP.*)$/\2/p' "$TMP_FILE")"
	REQUEST_URI_FILTRED="$(echo "$REQUEST_URI" | sed -r -e 's/\?/\\\?/g' -e 's/=[0-9]+/=\[0-9\]\+/g')"

	COOKIE="$(sed -n -r 's/^Cookie: (.*)/\1/p' "$TMP_FILE")"

	UNIQUE_ID_PARSED="$(sed -n -r 's/^\[.*\] (.{28})[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ [0-9]+ .*$/\1/p' "$TMP_FILE")"
}

head_message() {
	echo
	echo "To whitelist actions similar to unique ID: $UNIQUE_ID_PARSED, copy the above rule and press [Enter] to execute the commands:"
	echo
	echo "    nano /usr/share/modsecurity-crs.3/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
	echo "    systemctl reload apache2.service"
	echo "    systemctl status apache2.service"
}

rule_info() {
	echo "# Whitelist Rule $RULE_NUMBER Info -----"
	echo "#"
	echo "# Remote IP: $REMOTE_IP"
	echo "# Host:      $LOCAL_HOST"
	echo "# Request:   $REQUEST_FULL"
	echo "# Origin:    $ORIGIN_URL"
	echo "# Referer:   $REFERER_URL"
	echo "#"
}

rule_body() {
	printf "SecRule REQUEST_URI \"^%s$\" \\" "$REQUEST_URI_FILTRED"; echo
	printf "\t\"id:'%s', t:none, phase:1, pass, \\" "$RULE_NUMBER"; echo
	sed -r -n 's/.*\[id \"([0-9]+)\"\].*$/\t ctl:ruleRemoveById=\1\, \\/p' "$TMP_FILE" | sort -u | sed '$ s/\, \\/\"/'
}

edit_rules_and_rload_apache2() {
	read -p "Press [Enter] to continue, press [Ctrl+C] to cancel..."
	cp /usr/share/modsecurity-crs.3/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf{,.bak}
	nano /usr/share/modsecurity-crs.3/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
	systemctl reload apache2.service; echo; systemctl status apache2.service
}

script_variables() {
	echo; echo -------------------; echo
	echo "REQEST URI:     $REQUEST_URI"
	echo "REQEST URI FLT: $REQUEST_URI_FILTRED"
	echo
	echo "UNIQUE_ID_PARS: $UNIQUE_ID_PARSED"
	echo
	echo "COOKIE:"
	echo "$COOKIE"
	echo; echo -------------------; echo
}

#
# The Main Section -----

[[ -z ${1+x} ]] && RULE_NUMBER='999999' || RULE_NUMBER="$1"
[[ -z ${2+x} ]] && ANALYSIS_TYPE='latest-log' || ANALYSIS_TYPE="$2"
[[ -z ${3+x} ]] && UNIQUE_ID='The Unique ID must be 27 characters long!' || UNIQUE_ID="$3"

if   [[ $ANALYSIS_TYPE == "latest-log" ]]
then sed -n '/-A--/h;//!H;$!d;x;//p' "$LOG_FILE" > "$TMP_FILE"
elif [[ $ANALYSIS_TYPE == "unique-id"  ]] && [[ ! -z ${UNIQUE_ID} ]] && [[ ${#UNIQUE_ID} -eq 27 ]]
then sed -n "/${UNIQUE_ID}/,$ p" "$LOG_FILE" | sed '/-Z--/,$d' > "$TMP_FILE"
else
	echo
	echo "## The correct syntac must be:"
	echo
	echo -e "\t modsecurity-white-list-rule-generator '999999' 'latest-log'\n"
	echo -e "\t modsecurity-white-list-rule-generator '999999' 'unique-id' '27-CharactersLong-UniqueID'\n"
	exit 0
fi

get_info
#script_variables
head_message
echo; echo -e "${YEL}"
rule_info
rule_body
echo; echo -e "${NCL}"
edit_rules_and_rload_apache2
