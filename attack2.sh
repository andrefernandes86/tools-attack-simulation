#!/bin/bash

# SAFE HARNESS: Menu + logging + summaries only (no offensive actions).
# This fixes the original control flow and lets you test orchestration safely.

set -Eeuo pipefail

# --- Configuration ---
TARGET_NETWORK="192.168.40.0/24"
USERNAME="skynet"
PASSWORD="M@ster123"
RESULTS_DIR="$(pwd)/aggressive-security-test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAX_THREADS=32
SCAN_RATE=10000
BRUTE_FORCE_THREADS=16
CONCURRENT_CONTAINERS=20   # not used here but kept for parity

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"
LOG_FILE="$RESULTS_DIR/safe-harness-$TIMESTAMP.log"

log()      { echo -e "${GREEN}[$(date '+%F %T')] $*${NC}" | tee -a "$LOG_FILE"; }
error()    { echo -e "${RED}[ERROR] $*${NC}" | tee -a "$LOG_FILE"; }
warning()  { echo -e "${YELLOW}[WARNING] $*${NC}" | tee -a "$LOG_FILE"; }
info()     { echo -e "${BLUE}[INFO] $*${NC}" | tee -a "$LOG_FILE"; }
attack()   { echo -e "${PURPLE}[ATTACK] $*${NC}" | tee -a "$LOG_FILE"; }

# --- Safe stub runner ---
run_stub_test() {
  local test_name="$1"
  local duration="${2:-3}"     # seconds
  local outfile="$RESULTS_DIR/${test_name}_${TIMESTAMP}.txt"

  attack "Starting: $test_name (SAFE STUB)"
  {
    echo "=== $test_name ==="
    echo "Timestamp: $(date)"
    echo "Target Network: $TARGET_NETWORK"
    echo "User: $USERNAME"
    echo "Threads: MAX=$MAX_THREADS BRUTE=$BRUTE_FORCE_THREADS  ScanRate=$SCAN_RATE pps"
    for i in $(seq 1 "$duration"); do
      echo "Simulating $test_name step $i/$duration..."
      sleep 1
    done
    echo "Result: SAFE stub completed for $test_name"
  } >"$outfile"
  attack "$test_name COMPLETED (SAFE)"
}

# --- Safe versions of your test functions ---
test_aggressive_network_discovery()      { run_stub_test "massive_network_discovery" 3; }
test_aggressive_port_scanning()          { run_stub_test "ultrafast_port_scanning" 3; }
test_aggressive_service_detection()      { run_stub_test "aggressive_service_detection" 3; }
test_intensive_ssh_bruteforce()          { run_stub_test "intensive_ssh_bruteforce" 2; }
test_multiprotocol_bruteforce_storm()    { run_stub_test "multiprotocol_bruteforce_storm" 3; }
test_vulnerability_exploitation()        { run_stub_test "vulnerability_exploitation" 2; }
test_web_attack_storm()                  { run_stub_test "web_attack_storm" 3; }
test_smb_attack_storm()                  { run_stub_test "smb_attack_storm" 3; }
test_dns_attack_storm()                  { run_stub_test "dns_attack_storm" 2; }
test_network_traffic_flood()             { run_stub_test "network_traffic_flood" 2; }
test_database_attack_storm()             { run_stub_test "database_attack_storm" 3; }
test_stealth_evasion_storm()             { run_stub_test "stealth_evasion_storm" 2; }
test_protocol_fuzzing()                  { run_stub_test "protocol_fuzzing" 2; }
test_initial_access_simulation()         { run_stub_test "initial_access_simulation" 2; }
test_persistence_simulation()            { run_stub_test "persistence_simulation" 2; }
test_privilege_escalation_simulation()   { run_stub_test "privilege_escalation_simulation" 2; }
test_defense_evasion_simulation()        { run_stub_test "defense_evasion_simulation" 2; }
test_credential_access_simulation()      { run_stub_test "credential_access_simulation" 2; }
test_discovery_simulation()              { run_stub_test "discovery_simulation" 2; }
test_lateral_movement_simulation()       { run_stub_test "lateral_movement_simulation" 2; }
test_data_collection_simulation()        { run_stub_test "data_collection_simulation" 2; }
test_covert_channel_simulation()         { run_stub_test "covert_channel_simulation" 2; }
test_data_exfiltration_simulation()      { run_stub_test "data_exfiltration_simulation" 2; }
test_ransomware_simulation()             { run_stub_test "ransomware_simulation" 2; }
test_apt_simulation()                    { run_stub_test "apt_simulation" 2; }

# --- Phase submenu (wired correctly) ---
phase_menu() {
  echo "Select Kill Chain Phase:"
  echo "1) Initial Access & Reconnaissance"
  echo "2) Persistence & Privilege Escalation"
  echo "3) Defense Evasion & Lateral Movement"
  echo "4) Collection & Exfiltration"
  echo "5) Advanced Persistent Threats"
  read -rp "Enter phase (1-5): " phase_choice

  case "$phase_choice" in
    1)
      attack "Running PHASE 1: Initial Access & Reconnaissance"
      test_aggressive_network_discovery &
      test_initial_access_simulation &
      test_discovery_simulation &
      wait
      ;;
    2)
      attack "Running PHASE 2: Persistence & Privilege Escalation"
      test_persistence_simulation &
      test_privilege_escalation_simulation &
      test_credential_access_simulation &
      wait
      ;;
    3)
      attack "Running PHASE 3: Defense Evasion & Lateral Movement"
      test_defense_evasion_simulation &
      test_lateral_movement_simulation &
      test_covert_channel_simulation &
      wait
      ;;
    4)
      attack "Running PHASE 4: Collection & Exfiltration"
      test_data_collection_simulation &
      test_data_exfiltration_simulation &
      test_ransomware_simulation &
      wait
      ;;
    5)
      attack "Running PHASE 5: Advanced Persistent Threats"
      test_apt_simulation &
      test_covert_channel_simulation &
      wait
      ;;
    *)
      warning "Invalid phase choice. Running full kill chain (SAFE stubs)."
      run_ultimate_aggressive_tests
      ;;
  esac
}

# --- Orchestrations ---
run_ultimate_aggressive_tests() {
  attack "LAUNCHING SAFE CYBER KILL CHAIN SIMULATION"

  # Phase 1
  attack "PHASE 1: INITIAL ACCESS & RECONNAISSANCE"
  test_aggressive_network_discovery &
  sleep 1
  test_initial_access_simulation &
  sleep 1
  test_aggressive_port_scanning &
  sleep 1
  test_discovery_simulation &
  sleep 1

  # Phase 2
  attack "PHASE 2: PERSISTENCE & PRIVILEGE ESCALATION"
  test_persistence_simulation &
  sleep 1
  test_privilege_escalation_simulation &
  sleep 1
  test_intensive_ssh_bruteforce &
  sleep 1
  test_credential_access_simulation &
  sleep 1

  # Phase 3
  attack "PHASE 3: DEFENSE EVASION & LATERAL MOVEMENT"
  test_defense_evasion_simulation &
  sleep 1
  test_lateral_movement_simulation &
  sleep 1
  test_stealth_evasion_storm &
  sleep 1
  test_covert_channel_simulation &
  sleep 1

  # Phase 4
  attack "PHASE 4: DATA COLLECTION & EXFILTRATION"
  test_data_collection_simulation &
  sleep 1
  test_data_exfiltration_simulation &
  sleep 1
  test_ransomware_simulation &
  sleep 1
  test_apt_simulation &
  sleep 1

  # Phase 5
  attack "PHASE 5: ADVANCED PERSISTENT THREATS"
  test_multiprotocol_bruteforce_storm &
  sleep 1
  test_vulnerability_exploitation &
  sleep 1
  test_web_attack_storm &
  sleep 1
  test_database_attack_storm &
  sleep 1
  test_protocol_fuzzing &

  # Simple monitor
  while jobs -r >/dev/null; do
    active=$(jobs -r | wc -l | tr -d ' ')
    attack "Active SAFE tasks: $active"
    sleep 2
    [ "$active" -eq 0 ] && break
  done

  attack "SAFE KILL CHAIN SIMULATION FINISHED"
}

run_extreme_mode() {
  attack "ENTERING SAFE EXTREME MODE"
  for round in {1..2}; do
    attack "Round $round (SAFE)"
    for instance in {1..3}; do
      test_aggressive_network_discovery &
      test_aggressive_port_scanning   &
      test_multiprotocol_bruteforce_storm &
      test_network_traffic_flood &
      sleep 1
    done
    wait
  done
  attack "SAFE EXTREME MODE COMPLETED"
}

generate_aggressive_summary() {
  local summary="$RESULTS_DIR/safe-summary-$TIMESTAMP.txt"
  attack "Generating summary..."
  {
    echo "SAFE Security Testing Harness Summary"
    echo "Timestamp: $(date)"
    echo "Target: $TARGET_NETWORK"
    echo "User: $USERNAME"
    echo "Results dir: $RESULTS_DIR"
    echo
    echo "Files:"
    ls -la "$RESULTS_DIR"/*_"$TIMESTAMP".txt 2>/dev/null || echo "No result files."
    echo
    echo "Counts:"
    echo "- Total files: $(ls "$RESULTS_DIR"/*_"$TIMESTAMP".txt 2>/dev/null | wc -l || echo 0)"
    echo "- Total size: $(du -sh "$RESULTS_DIR" | cut -f1)"
  } >"$summary"
  attack "Summary saved to: $summary"
}

aggressive_cleanup() {
  attack "Safe cleanup: removing local stub files only"
  find "$RESULTS_DIR" -type f -name "*_${TIMESTAMP}.txt" -delete 2>/dev/null || true
  attack "Cleanup done"
}

banner() {
  echo -e "${RED}"
  cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                SAFE SECURITY TESTING HARNESS              ║
║         Orchestration, logging, and summaries only        ║
╚═══════════════════════════════════════════════════════════╝
EOF
  echo -e "${NC}"
}

main() {
  banner
  attack "INIT"
  attack "Target Network: $TARGET_NETWORK"
  attack "Using Credentials: $USERNAME/$PASSWORD"
  attack "Results Directory: $RESULTS_DIR"
  attack "Max Threads: $MAX_THREADS | Scan Rate: $SCAN_RATE pps"

  echo
  warning "This harness does NOT run offensive actions. It simulates them for testing."
  echo

  read -rp "Type 'SAFE' to continue: " confirmation
  if [[ "$confirmation" != "SAFE" ]]; then
    error "Confirmation failed. Exiting."
    exit 1
  fi

  echo
  echo "Select execution mode:"
  echo "1) Ultimate Cyber Kill Chain (SAFE stubs)"
  echo "2) Extreme Mode (SAFE stubs)"
  echo "3) Individual Kill Chain Phase (SAFE stubs)"
  echo "4) Cleanup only"
  echo
  read -rp "Enter your choice (1-4): " choice

  case "$choice" in
    1) run_ultimate_aggressive_tests ;;
    2) run_extreme_mode ;;
    3) phase_menu ;;
    4) aggressive_cleanup; exit 0 ;;
    *) warning "Invalid choice. Running Ultimate (SAFE) by default."
       run_ultimate_aggressive_tests ;;
  esac

  generate_aggressive_summary
  aggressive_cleanup

  attack "SAFE HARNESS COMPLETED"
  echo -e "\n${CYAN}Review the logs in: $RESULTS_DIR${NC}"
}

trap aggressive_cleanup EXIT INT TERM
main "$@"
