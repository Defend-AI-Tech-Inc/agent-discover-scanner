#!/bin/bash
#
# AgentDiscover Scanner - Universal Installer
# 
# Automatically detects your environment and installs required components:
#   - Python scanner (from PyPI or source)
#   - osquery (for Layer 4 - endpoint discovery)
#   - Cilium/Tetragon (for Layers 2-3 - K8s monitoring, if applicable)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash
#   OR
#   ./install.sh [--non-interactive] [--layers 1,2,3,4] [--source]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INTERACTIVE=true
INSTALL_LAYERS="1,4"  # Default: Code + Endpoint (no K8s required)
INSTALL_FROM_SOURCE=false
PYTHON_MIN_VERSION="3.10"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --non-interactive|-n)
            INTERACTIVE=false
            shift
            ;;
        --layers|-l)
            INSTALL_LAYERS="$2"
            shift 2
            ;;
        --source|-s)
            INSTALL_FROM_SOURCE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --non-interactive, -n    Run without prompts (use defaults)"
            echo "  --layers, -l LAYERS      Comma-separated layers to install (default: 1,4)"
            echo "  --source, -s             Install from source instead of PyPI"
            echo "  --help, -h               Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                       # Interactive install, layers 1+4"
            echo "  $0 --layers 1,2,3,4      # Install all layers"
            echo "  $0 --non-interactive     # Automated install"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run with --help for usage"
            exit 1
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect Python
detect_python() {
    # Try different Python commands
    for cmd in python3.12 python3.11 python3.10 python3.9 python3.8 python3 python; do
        if command -v "$cmd" &> /dev/null; then
            PYTHON_CMD="$cmd"
            # Use sed instead of grep -oP for better compatibility
            PYTHON_VERSION=$($cmd --version 2>&1 | sed -E 's/.*([0-9]+\.[0-9]+).*/\1/' | head -1)
            return 0
        fi
    done
    return 1
}

# Print banner
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║          AgentDiscover Scanner v2.0 Installer              ║"
echo "║                                                            ║"
echo "║  Four-layer AI discovery - from code to endpoints         ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Detect OS
log_info "Detecting operating system..."

OS="$(uname -s)"
case "${OS}" in
    Linux*)     
        MACHINE="Linux"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO=$ID
            DISTRO_VERSION=$VERSION_ID
        else
            DISTRO="unknown"
        fi
        ;;
    Darwin*)    
        MACHINE="macOS"
        DISTRO="macos"
        ;;
    MINGW*|MSYS*|CYGWIN*)     
        MACHINE="Windows"
        DISTRO="windows"
        ;;
    *)          
        MACHINE="Unknown:${OS}"
        ;;
esac

log_success "Detected: $MACHINE ($DISTRO)"

# Step 2: Check if running in Kubernetes
log_info "Checking for Kubernetes..."

K8S_AVAILABLE=false
if command_exists kubectl; then
    if kubectl cluster-info >/dev/null 2>&1; then
        K8S_AVAILABLE=true
        K8S_VERSION=$(kubectl version --short 2>/dev/null | grep Server | awk '{print $3}')
        log_success "Kubernetes detected: $K8S_VERSION"
    else
        log_warning "kubectl found but no cluster connection"
    fi
else
    log_info "Kubernetes not available (kubectl not found)"
fi

# Step 3: Check Python version
log_info "Checking Python version..."

if ! detect_python; then
    log_error "Python 3 not found. Please install Python 3.10 or higher."
    log_info "On Ubuntu/Debian: apt install python3"
    log_info "On macOS: brew install python@3.10"
    exit 1
fi

# Verify minimum version (3.10)
if ! $PYTHON_CMD -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
    log_error "Python $PYTHON_VERSION found, but 3.10+ required"
    exit 1
fi

log_success "Python $PYTHON_VERSION detected (meets requirement >= $PYTHON_MIN_VERSION)"

# Step 4: Determine which layers to install
log_info "Installation plan: Layers $INSTALL_LAYERS"

IFS=',' read -ra LAYERS <<< "$INSTALL_LAYERS"
INSTALL_LAYER_1=false
INSTALL_LAYER_2=false
INSTALL_LAYER_3=false
INSTALL_LAYER_4=false

for layer in "${LAYERS[@]}"; do
    case "$layer" in
        1) INSTALL_LAYER_1=true ;;
        2) INSTALL_LAYER_2=true ;;
        3) INSTALL_LAYER_3=true ;;
        4) INSTALL_LAYER_4=true ;;
        *) log_warning "Unknown layer: $layer" ;;
    esac
done

# Interactive confirmation
if [ "$INTERACTIVE" = true ]; then
    echo ""
    echo "Installation Configuration:"
    echo "  OS: $MACHINE"
    echo "  Python: $PYTHON_VERSION"
    echo "  Kubernetes: $([ "$K8S_AVAILABLE" = true ] && echo "Yes" || echo "No")"
    echo ""
    echo "Components to install:"
    echo "  [$([ "$INSTALL_LAYER_1" = true ] && echo "✓" || echo " ")] Layer 1: Code Discovery"
    echo "  [$([ "$INSTALL_LAYER_2" = true ] && echo "✓" || echo " ")] Layer 2: Network Discovery $([ "$K8S_AVAILABLE" = false ] && echo "(requires K8s)" || echo "")"
    echo "  [$([ "$INSTALL_LAYER_3" = true ] && echo "✓" || echo " ")] Layer 3: Runtime Discovery $([ "$K8S_AVAILABLE" = false ] && echo "(requires K8s)" || echo "")"
    echo "  [$([ "$INSTALL_LAYER_4" = true ] && echo "✓" || echo " ")] Layer 4: Endpoint Discovery"
    echo ""
    
    read -p "Continue with installation? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
        log_info "Installation cancelled"
        exit 0
    fi
fi

# Step 5: Install Python scanner
echo ""
log_info "Installing AgentDiscover Scanner..."

if [ "$INSTALL_FROM_SOURCE" = true ]; then
    log_info "Installing from source..."
    
    if [ -f "setup.py" ]; then
        # Already in repo directory
        $PYTHON_CMD -m pip install -e .
    else
        # Need to clone repo
        if [ ! -d "agent-discover-scanner" ]; then
            git clone https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner.git
        fi
        cd agent-discover-scanner
        $PYTHON_CMD -m pip install -e .
        cd ..
    fi
else
    log_info "Installing from PyPI..."
    $PYTHON_CMD -m pip install --upgrade agent-discover-scanner
fi

# Verify installation
if command_exists agent-discover-scanner; then
    SCANNER_VERSION=$(agent-discover-scanner --version 2>/dev/null || echo "unknown")
    log_success "Scanner installed: $SCANNER_VERSION"
else
    log_error "Scanner installation failed"
    exit 1
fi

# Step 6: Install Layer 4 dependencies (osquery)
if [ "$INSTALL_LAYER_4" = true ]; then
    echo ""
    log_info "Installing Layer 4 dependencies (osquery)..."
    
    if command_exists osqueryi; then
        OSQUERY_VERSION=$(osqueryi --version 2>/dev/null | head -n1 || echo "unknown")
        log_success "osquery already installed: $OSQUERY_VERSION"
    else
        case $MACHINE in
            macOS)
                log_info "Installing osquery via Homebrew..."
                if command_exists brew; then
                    brew install osquery
                else
                    log_error "Homebrew not found. Install from https://brew.sh"
                    exit 1
                fi
                ;;
                
            Linux)

                            # Detect if we need sudo
                if [ "$EUID" -eq 0 ]; then
                    # Running as root (Docker, etc.)
                    SUDO=""
                else
                    # Running as regular user
                    SUDO="sudo"
                fi

                if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
                    log_info "Installing osquery via apt..."
                    
                    # Modern method: use signed-by instead of deprecated apt-key
                    export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
                    $SUDO mkdir -p /etc/apt/keyrings
                    
                    # Try modern method first
                    if curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/osquery.gpg 2>/dev/null; then
                        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" | sudo tee /etc/apt/sources.list.d/osquery.list
                    else
                        # Fallback to deprecated apt-key for older systems
                        log_warning "Using deprecated apt-key method (consider upgrading your system)"
                        $SUDO apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY 2>/dev/null || true
                        echo "deb [arch=amd64] https://pkg.osquery.io/deb deb main" | sudo tee /etc/apt/sources.list.d/osquery.list
                    fi
                    
                    $SUDO apt-get update
                    $SUDO apt-get install -y osquery
                    
                elif [ "$DISTRO" = "centos" ] || [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "fedora" ]; then
                    log_info "Installing osquery via yum/dnf..."
                    
                    curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
                    
                    # Use dnf if available (Fedora 22+, RHEL 8+), otherwise yum
                    if command_exists dnf; then
                        $SUDO dnf config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
                        $SUDO dnf install -y osquery
                    elif command_exists yum; then
                        $SUDO yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
                        $SUDO yum install -y osquery
                    else
                        log_error "Neither dnf nor yum found"
                        exit 1
                    fi
                else
                    log_error "Unsupported Linux distribution: $DISTRO"
                    log_info "Please install osquery manually: https://osquery.io/downloads"
                    exit 1
                fi
                ;;
                
            Windows)
                log_warning "Windows detected. Please install osquery manually:"
                log_info "  Download: https://osquery.io/downloads/official/5.11.0"
                log_info "  Or use Chocolatey: choco install osquery"
                exit 1
                ;;
                
            *)
                log_error "Unsupported OS for automatic osquery installation"
                log_info "Please install manually: https://osquery.io/downloads"
                exit 1
                ;;
        esac
        
        # Verify osquery installation
        if command_exists osqueryi; then
            OSQUERY_VERSION=$(osqueryi --version 2>/dev/null | head -n1)
            log_success "osquery installed: $OSQUERY_VERSION"
        else
            log_error "osquery installation failed"
            exit 1
        fi
    fi
fi

# Step 7: Install Layers 2-3 dependencies (Cilium/Tetragon)
if [ "$INSTALL_LAYER_2" = true ] || [ "$INSTALL_LAYER_3" = true ]; then
    echo ""
    log_info "Installing Layers 2-3 dependencies (Cilium/Tetragon)..."
    
    if [ "$K8S_AVAILABLE" = false ]; then
        log_error "Layers 2-3 require Kubernetes, but no cluster detected"
        log_info "Install kubectl and configure cluster access first"
        exit 1
    fi
    
    # Check if Cilium is already installed
    if kubectl get pods -n kube-system -l k8s-app=cilium >/dev/null 2>&1; then
        log_success "Cilium already installed"
    else
        log_info "Installing Cilium..."
        
        # Install Cilium CLI if not present
        if ! command_exists cilium; then
            log_info "Installing Cilium CLI..."
            
            CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
            CLI_ARCH=amd64
            if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
            
            curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
            sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
            sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
            rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
        fi
        
        # Install Cilium
        cilium install
        
        # Wait for Cilium to be ready
        log_info "Waiting for Cilium to be ready..."
        cilium status --wait
        
        log_success "Cilium installed"
    fi
    
    # Check if Tetragon is already installed
    if kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon >/dev/null 2>&1; then
        log_success "Tetragon already installed"
    else
        log_info "Installing Tetragon..."
        
        # Install Tetragon via Helm
        if ! command_exists helm; then
            log_error "Helm not found. Install from https://helm.sh/docs/intro/install/"
            exit 1
        fi
        
        helm repo add cilium https://helm.cilium.io
        helm repo update
        
        helm install tetragon cilium/tetragon \
            --namespace kube-system \
            --set tetragon.enableProcessCred=true \
            --set tetragon.enableProcessNs=true
        
        log_success "Tetragon installed"
    fi
fi

# Step 8: Verify installation
echo ""
log_info "Verifying installation..."
echo ""

# Test scanner
if agent-discover-scanner --version >/dev/null 2>&1; then
    log_success "✓ AgentDiscover Scanner working"
else
    log_error "✗ Scanner verification failed"
    exit 1
fi

# Test Layer 4 (osquery)
if [ "$INSTALL_LAYER_4" = true ]; then
    if osqueryi --version >/dev/null 2>&1; then
        log_success "✓ osquery working (Layer 4 ready)"
    else
        log_error "✗ osquery not working"
        exit 1
    fi
fi

# Test Layers 2-3 (K8s)
if [ "$INSTALL_LAYER_2" = true ] || [ "$INSTALL_LAYER_3" = true ]; then
    if kubectl get pods -n kube-system -l k8s-app=cilium | grep -q Running; then
        log_success "✓ Cilium running (Layers 2-3 ready)"
    else
        log_warning "⚠ Cilium not fully ready yet"
    fi
fi

# Step 9: Run test scan
echo ""
log_info "Running test scan..."
echo ""

# Determine which layers to test
TEST_LAYERS=""
[ "$INSTALL_LAYER_1" = true ] && TEST_LAYERS="${TEST_LAYERS}1,"
[ "$INSTALL_LAYER_2" = true ] && TEST_LAYERS="${TEST_LAYERS}2,"
[ "$INSTALL_LAYER_3" = true ] && TEST_LAYERS="${TEST_LAYERS}3,"
[ "$INSTALL_LAYER_4" = true ] && TEST_LAYERS="${TEST_LAYERS}4,"
TEST_LAYERS=${TEST_LAYERS%,}  # Remove trailing comma

if [ -n "$TEST_LAYERS" ]; then
    agent-discover-scanner scan --layers "$TEST_LAYERS" --output test_scan_report.md || true
    
    if [ -f "test_scan_report.md" ]; then
        log_success "Test scan completed: test_scan_report.md"
    fi
else
    log_warning "No layers to test"
fi

# Step 10: Print summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║              Installation Complete! ✓                      ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

echo "Installed components:"
[ "$INSTALL_LAYER_1" = true ] && echo "  ✓ Layer 1: Code Discovery"
[ "$INSTALL_LAYER_2" = true ] && echo "  ✓ Layer 2: Network Discovery"
[ "$INSTALL_LAYER_3" = true ] && echo "  ✓ Layer 3: Runtime Discovery"
[ "$INSTALL_LAYER_4" = true ] && echo "  ✓ Layer 4: Endpoint Discovery"
echo ""

echo "Quick start commands:"
echo ""
echo "  # Scan local machine (code + endpoint)"
echo "  agent-discover-scanner scan --layers 1,4"
echo ""

if [ "$INSTALL_LAYER_4" = true ]; then
    echo "  # Scan just this endpoint (Shadow AI)"
    echo "  agent-discover-scanner layer4"
    echo ""
fi

if [ "$K8S_AVAILABLE" = true ] && ([ "$INSTALL_LAYER_2" = true ] || [ "$INSTALL_LAYER_3" = true ]); then
    echo "  # Full scan (all layers)"
    echo "  agent-discover-scanner scan --layers 1,2,3,4"
    echo ""
fi

echo "Documentation:"
echo "  https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner"
echo ""

log_success "Happy scanning!"
echo ""
