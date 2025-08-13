#!/bin/bash

# Autonomous Security Testing Lab for Trend Micro Solutions
# Target Network: 192.168.40.0/24
# Test Credentials: skynet/M@ster123

set -e

# Configuration
TARGET_NETWORK="192.168.40.0/24"
USERNAME="skynet"
PASSWORD="M@ster123"
RESULTS_DIR="$(pwd)/security-test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "$RESULTS_DIR"
LOG_FILE="$RESULTS_DIR/test-execution-$TIMESTAMP.log"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}" | tee -a "$LOG_FILE"
}

# Check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        error "Docker is not running or not accessible"
        exit 1
    fi
    log "Docker is running"
}

# Pull required images
pull_images() {
    log "Pulling required Docker images..."
    
    images=(
        "kalilinux/kali-rolling"
        "instrumentisto/nmap"
        "vanhauser/hydra"
        "owasp/zap2docker-stable"
        "rustscan/rustscan:latest"
        "nicolaka/netshoot"
        "vulners/nmap"
    )
    
    for image in "${images[@]}"; do
        info "Pulling $image..."
        docker pull "$image" 2>/dev/null || warning "Failed to pull $image"
    done
}

# Function to run container and capture output
run_test() {
    local test_name="$1"
    local container_cmd="$2"
    local output_file="$RESULTS_DIR/${test_name}_${TIMESTAMP}.txt"
    
    log "Starting: $test_name"
    info "Command: $container_cmd"
    info "Output will be saved to: $output_file"
    
    # Run the container and capture output
    eval "$container_cmd" > "$output_file" 2>&1 &
    local pid=$!
    
    # Wait for completion with timeout (10 minutes per test)
    local timeout=600
    local elapsed=0
    while kill -0 $pid 2>/dev/null && [ $elapsed -lt $timeout ]; do
        sleep 5
        elapsed=$((elapsed + 5))
        echo -n "."
    done
    echo
    
    if kill -0 $pid 2>/dev/null; then
        kill $pid 2>/dev/null || true
        warning "$test_name timed out after ${timeout}s"
    else
        log "$test_name completed"
    fi
}

# Test 1: Network Discovery
test_network_discovery() {
    run_test "network_discovery" \
        "docker run --rm --network host instrumentisto/nmap -sn $TARGET_NETWORK"
}

# Test 2: Port Scanning (Fast)
test_port_scanning() {
    run_test "port_scanning" \
        "docker run --rm --network host rustscan/rustscan:latest -a $TARGET_NETWORK -u 5000 -- -sV"
}

# Test 3: Comprehensive Nmap Scan
test_comprehensive_scan() {
    run_test "comprehensive_scan" \
        "docker run --rm --network host instrumentisto/nmap -sS -sV -O --script vuln $TARGET_NETWORK"
}

# Test 4: SSH Brute Force
test_ssh_bruteforce() {
    run_test "ssh_bruteforce" \
        "docker run --rm --network host vanhauser/hydra -l $USERNAME -p $PASSWORD -t 4 -V $TARGET_NETWORK ssh"
}

# Test 5: RDP Brute Force
test_rdp_bruteforce() {
    run_test "rdp_bruteforce" \
        "docker run --rm --network host vanhauser/hydra -l $USERNAME -p $PASSWORD -t 4 -V $TARGET_NETWORK rdp"
}

# Test 6: SMB Enumeration and Testing
test_smb_enumeration() {
    run_test "smb_enumeration" \
        'docker run --rm --network host kalilinux/kali-rolling bash -c "
            apt-get update -qq && apt-get install -y -qq smbclient enum4linux nbtscan 2>/dev/null;
            echo \"=== NBTSCAN ===\";
            nbtscan '"$TARGET_NETWORK"';
            echo \"=== SMB ENUMERATION ===\";
            for i in {1..254}; do
                timeout 5 enum4linux '"192.168.40.\$i"' 2>/dev/null | grep -v \"^$\" || true;
            done
        "'
}

# Test 7: Web Application Scanning
test_web_scanning() {
    run_test "web_scanning" \
        'docker run --rm --network host kalilinux/kali-rolling bash -c "
            apt-get update -qq && apt-get install -y -qq nikto dirb gobuster 2>/dev/null;
            echo \"=== WEB DISCOVERY ===\";
            nmap -p 80,443,8080,8443 --open '"$TARGET_NETWORK"';
            echo \"=== NIKTO SCAN ===\";
            for i in {1..254}; do
                timeout 30 nikto -h http://192.168.40.\$i 2>/dev/null || true;
            done
        "'
}

# Test 8: Vulnerability Scanning
test_vulnerability_scan() {
    run_test "vulnerability_scan" \
        "docker run --rm --network host vulners/nmap -sV --script vulners --script-args mincvss=5.0 $TARGET_NETWORK"
}

# Test 9: DNS Enumeration
test_dns_enumeration() {
    run_test "dns_enumeration" \
        'docker run --rm --network host kalilinux/kali-rolling bash -c "
            apt-get update -qq && apt-get install -y -qq dnsutils dnsrecon 2>/dev/null;
            echo \"=== DNS DISCOVERY ===\";
            nmap -sU -p 53 --script dns-* '"$TARGET_NETWORK"';
            echo \"=== DNS ENUMERATION ===\";
            dnsrecon -r '"$TARGET_NETWORK"' 2>/dev/null || true
        "'
}

# Test 10: Traffic Generation
test_traffic_generation() {
    run_test "traffic_generation" \
        'docker run --rm --network host nicolaka/netshoot bash -c "
            echo \"=== GENERATING NETWORK TRAFFIC ===\";
            for i in {1..254}; do
                timeout 2 ping -c 1 192.168.40.\$i &
                timeout 2 nc -zv 192.168.40.\$i 22 2>/dev/null &
                timeout 2 nc -zv 192.168.40.\$i 80 2>/dev/null &
                timeout 2 nc -zv 192.168.40.\$i 443 2>/dev/null &
            done;
            wait;
            echo \"Traffic generation completed\"
        "'
}

# Test 11: Multi-Protocol Brute Force
test_multiprotocol_bruteforce() {
    run_test "multiprotocol_bruteforce" \
        'docker run --rm --network host kalilinux/kali-rolling bash -c "
            apt-get update -qq && apt-get install -y -qq hydra medusa patator 2>/dev/null;
            echo \"=== HYDRA MULTI-PROTOCOL TEST ===\";
            echo '"$USERNAME"' > /tmp/users.txt;
            echo '"$PASSWORD"' > /tmp/passwords.txt;
            timeout 300 hydra -L /tmp/users.txt -P /tmp/passwords.txt -t 8 -f '"$TARGET_NETWORK"' ssh || true;
            timeout 300 hydra -L /tmp/users.txt -P /tmp/passwords.txt -t 8 -f '"$TARGET_NETWORK"' ftp || true;
            timeout 300 hydra -L /tmp/users.txt -P /tmp/passwords.txt -t 8 -f '"$TARGET_NETWORK"' telnet || true
        "'
}

# Test 12: Stealth Scanning
test_stealth_scanning() {
    run_test "stealth_scanning" \
        "docker run --rm --network host instrumentisto/nmap -sS -f -T1 -D RND:5 $TARGET_NETWORK"
}

# Parallel execution function
run_parallel_tests() {
    log "Starting parallel security tests..."
    
    # Start background tests
    test_network_discovery &
    sleep 10
    test_port_scanning &
    sleep 15
    test_comprehensive_scan &
    sleep 20
    test_ssh_bruteforce &
    sleep 10
    test_rdp_bruteforce &
    sleep 15
    test_smb_enumeration &
    sleep 20
    test_web_scanning &
    sleep 10
    test_vulnerability_scan &
    sleep 15
    test_dns_enumeration &
    sleep 10
    test_traffic_generation &
    sleep 20
    test_multiprotocol_bruteforce &
    sleep 10
    test_stealth_scanning &
    
    # Wait for all background jobs to complete
    wait
    log "All parallel tests completed"
}

# Sequential execution function
run_sequential_tests() {
    log "Starting sequential security tests..."
    
    test_network_discovery
    test_port_scanning
    test_comprehensive_scan
    test_ssh_bruteforce
    test_rdp_bruteforce
    test_smb_enumeration
    test_web_scanning
    test_vulnerability_scan
    test_dns_enumeration
    test_traffic_generation
    test_multiprotocol_bruteforce
    test_stealth_scanning
    
    log "All sequential tests completed"
}

# Generate summary report
generate_summary() {
    local summary_file="$RESULTS_DIR/test-summary-$TIMESTAMP.txt"
    
    log "Generating test summary..."
    
    cat > "$summary_file" << EOF
Security Testing Lab Summary Report
===================================
Timestamp: $(date)
Target Network: $TARGET_NETWORK
Test Credentials: $USERNAME/$PASSWORD
Results Directory: $RESULTS_DIR

Test Files Generated:
EOF
    
    ls -la "$RESULTS_DIR"/*_$TIMESTAMP.txt >> "$summary_file" 2>/dev/null || echo "No test files found" >> "$summary_file"
    
    info "Summary report saved to: $summary_file"
}

# Cleanup function
cleanup() {
    log "Cleaning up containers..."
    docker container prune -f 2>/dev/null || true
    log "Cleanup completed"
}

# Main execution
main() {
    echo -e "${GREEN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║          Autonomous Security Testing Lab                  ║
║          For Trend Micro Solution Testing                 ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    log "Starting security testing lab for network: $TARGET_NETWORK"
    log "Using credentials: $USERNAME/$PASSWORD"
    log "Results will be saved to: $RESULTS_DIR"
    
    check_docker
    pull_images
    
    # Ask user for execution mode
    echo
    echo "Select execution mode:"
    echo "1) Sequential (tests run one after another - safer, slower)"
    echo "2) Parallel (tests run simultaneously - faster, more intensive)"
    echo "3) Cleanup only (remove containers and exit)"
    echo
    read -p "Enter your choice (1-3): " choice
    
    case $choice in
        1)
            run_sequential_tests
            ;;
        2)
            run_parallel_tests
            ;;
        3)
            cleanup
            exit 0
            ;;
        *)
            warning "Invalid choice. Running sequential tests by default."
            run_sequential_tests
            ;;
    esac
    
    generate_summary
    cleanup
    
    log "Security testing lab completed successfully!"
    log "Check the results in: $RESULTS_DIR"
    
    echo -e "\n${GREEN}Testing completed! Your Trend Micro solutions should have detected and logged these security events.${NC}"
    echo -e "${BLUE}Review the generated reports in: $RESULTS_DIR${NC}"
}

# Handle script interruption
trap cleanup EXIT INT TERM

# Run main function
main "$@"
