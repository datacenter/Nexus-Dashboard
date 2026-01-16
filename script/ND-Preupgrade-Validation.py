#!/usr/bin/env python3
"""
Nexus Dashboard Pre-upgrade Validation Script

This script performs health checks on a Nexus Dashboard cluster:
- Each node processes its own tech support files locally
- All validation checks run in parallel across the cluster
- Results are aggregated at the end for a comprehensive report

Author: joelebla@cisco.com
Version: 1.0.11 (Jan 16, 2026)
"""

import re
import subprocess
import threading
import platform
import socket
import time
import sys
import os
import json
import math
import shlex
import getpass
import glob
import signal
import tempfile
import platform
import traceback
import argparse
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set up logging
def setup_logging():
    """Set up logging configuration"""
    log_dir = os.path.expanduser("~/nd_validation_logs")
    try:
        os.makedirs(log_dir)
    except OSError:
        pass  # Directory already exists
    
    log_file = "{}/nd_validation_{}.log".format(log_dir, datetime.now().strftime('%Y%m%d'))
    
    # Get the current script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create debug log in script directory (will be moved to final-results later)
    debug_log = os.path.join(script_dir, "nd_validation_debug.log")
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file)
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    # Add console handler with higher log level
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)  # Only INFO and above show on console
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Configure file handler for debug logging
    debug_handler = logging.FileHandler(debug_log)
    debug_handler.setLevel(logging.DEBUG)
    debug_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    debug_handler.setFormatter(debug_formatter)
    logger.addHandler(debug_handler)
    
    # Downgrade INFO messages to DEBUG for console
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler) and handler.level == logging.INFO:
            handler.setLevel(logging.ERROR)  # Only show errors on console
    
    console_handler.setLevel(logging.ERROR)
    
    return logger

# Initialize logger as None - will be set up in main()
logger = None  

# Set up formatting constants
PASS = "\033[1;32mPASS\033[0m"
FAIL = "\033[1;31mFAIL\033[0m"
WARNING = "\033[1;33mWARNING\033[0m"

def check_environment():
    """
    Check if the environment has all required dependencies installed.
    Returns a tuple of (ready, missing_dependencies, installation_instructions)
    """
    # List of required external programs
    required_programs = {
        "sshpass": "sshpass is required for password-based SSH authentication"
    }
    
    # List of required Python modules
    required_modules = [
        "concurrent", # For ThreadPoolExecutor
        "json",       # For JSON handling
        "re",         # For regex
        "logging",    # For logging
        "datetime",   # For date/time operations
        "argparse",   # For command line arguments
        "getpass",    # For password input
        "tempfile",   # For temporary file handling
        "shlex",      # For shell command escaping
        "signal",     # For signal handling
        "subprocess", # For running external commands
        "threading",  # For threading support
        "math",       # For math functions
        "traceback"   # For exception traceback
    ]
    
    # Check if we're running on APIC
    is_apic = False
    try:
        # More reliable APIC detection methods
        if os.path.exists("/aci"):  # APIC has /aci directory
            is_apic = True
        elif "admin@" in os.environ.get("PS1", "") and os.path.exists("/mit"):  # PS1 environment variable and /mit directory
            is_apic = True
        elif subprocess.call("which acidiag >/dev/null 2>&1", shell=True) == 0:  # Check for acidiag command
            is_apic = True
            
        if is_apic:
            logger.info("Detected APIC environment")
    except:
        pass
    
    # Check if we're running in Windows
    is_windows = platform.system() == "Windows"
    
    missing = []
    
    # Check external programs (skip sshpass check on Windows or APIC)
    if not is_windows and not is_apic:
        for program, description in required_programs.items():
            # Check if the program is in PATH
            try:
                subprocess.run(["which", program], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, 
                              check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                missing.append(f"External program: {program} - {description}")
    
    # Check Python modules
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(f"Python module: {module}")
    
    # Generate installation instructions
    instructions = []
    
    if missing and not is_apic:  # Skip instructions for APIC
        if is_windows:
            instructions.append("Windows detected. For best compatibility, consider running this script in WSL (Windows Subsystem for Linux).")
            instructions.append("\nFor external programs:")
            instructions.append("Install Git Bash or WSL and run 'apt-get install sshpass'")
        else:
            # Linux/MacOS instructions
            instructions.append("To install missing dependencies:")
            
            # Instructions for external programs
            program_missing = [dep for dep in missing if dep.startswith("External program")]
            if program_missing:
                instructions.append("\nFor external programs:")
                instructions.append("sudo apt-get update")
                instructions.append("sudo apt-get install sshpass")
            
            # Instructions for Python modules
            module_missing = [dep for dep in missing if dep.startswith("Python module")]
            if module_missing:
                instructions.append("\nFor Python modules:")
                instructions.append("No additional Python modules required")
        
        instructions.append("\nAfter installing dependencies, run this script again.")
        instructions.append("Or use --ignore-deps flag to run anyway.")
    
    # Success if no missing dependencies OR we're on APIC (auto-pass)
    return ((len(missing) == 0) or is_apic, missing, instructions)

class SSHCommand:
    """Context manager for handling SSH commands with proper cleanup"""
    
    def __init__(self, node_manager, node, command, mask_password=True):
        self.node_manager = node_manager
        self.node = node
        self.command = command
        self.mask_password = mask_password
        self.process = None
        self.stdout = None
        self.stderr = None
        self.returncode = None
        
    def __enter__(self):
        """Start the SSH command when entering context"""
        try:
            # Use centralized SSH command builder with connection multiplexing
            full_cmd = self.node_manager.build_ssh_command(self.node['ip'], self.command)
            
            # Create masked version for logs
            if self.mask_password:
                masked_cmd = full_cmd.replace(self.node_manager.password, "********")
                logger.debug(f"Executing SSH command (masked): {masked_cmd}")
            
            # Execute the command
            self.process = subprocess.Popen(
                full_cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            return self
        except Exception as e:
            logger.error(f"Error starting SSH command: {str(e)}")
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up resources when exiting context"""
        if self.process:
            try:
                # If process is still running, terminate it
                if self.returncode is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
            except:
                pass
        
        return False  # Don't suppress exceptions
    
    def get_results(self, timeout=None):
        """Get command results within the context"""
        if not self.process:
            return "", "", 1
            
        try:
            self.stdout, self.stderr = self.process.communicate(timeout=timeout)
            self.returncode = self.process.returncode
            
            stdout_str = self.stdout.decode('utf-8').strip()
            stderr_str = self.stderr.decode('utf-8').strip()
            
            # If we got a failure with no error message, try to get the actual SSH error
            if self.returncode != 0 and not stderr_str and not stdout_str:
                logger.debug(f"Empty error output from sshpass, attempting direct SSH diagnostic")
                try:
                    # Build SSH options string
                    ssh_opts = " ".join(self.node_manager.ssh_options)
                    if self.node_manager.legacy_ssh_mode:
                        ssh_opts += " -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa"
                    
                    # Try SSH without sshpass to see the actual error
                    diagnostic_cmd = f"ssh {ssh_opts} -o BatchMode=yes {self.node_manager.username}@{self.node['ip']} 'echo test' 2>&1"
                    logger.debug(f"Running diagnostic: {diagnostic_cmd}")
                    
                    diag_process = subprocess.Popen(diagnostic_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    diag_out, _ = diag_process.communicate(timeout=5)
                    diag_output = diag_out.decode('utf-8').strip()
                    
                    if diag_output:
                        logger.debug(f"Diagnostic output: {diag_output}")
                        stderr_str = diag_output
                except Exception as diag_e:
                    logger.debug(f"Diagnostic command failed: {str(diag_e)}")
            
            return (stdout_str, stderr_str, self.returncode)
            
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.stdout, self.stderr = self.process.communicate()
            self.returncode = self.process.returncode
            
            return (
                "Command timed out",
                self.stderr.decode('utf-8').strip(),
                self.returncode
            )
        
def is_valid_ip(ip):
    """Validate if the string is a valid IPv4 or IPv6 address"""
    try:
        import ipaddress
        # Try to parse as IPv4 or IPv6
        ipaddress.ip_address(ip)
        return True
    except (ValueError, AttributeError):
        return False

def check_system_resources():
    """
    Check system resources to determine optimal parallelism for worker script deployment.
    Returns a dictionary with resource information and recommended node concurrency.
    """
    resources = {}
    
    # Check for CPU count via /proc/cpuinfo
    try:
        cpu_count = 0
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('processor'):
                    cpu_count += 1
        resources["cpu_count"] = cpu_count
        logger.debug(f"Detected {cpu_count} CPU cores")
    except Exception as e:
        resources["cpu_count"] = 2  # Conservative default
        logger.debug(f"Couldn't read CPU info: {str(e)}. Assuming 2 cores.")
    
    # Check memory via /proc/meminfo
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    # Memory is in kB in /proc/meminfo
                    mem_kb = int(line.split()[1])
                    mem_gb = round(mem_kb / (1024 * 1024), 2)
                    resources["memory_gb"] = mem_gb
                    logger.debug(f"Detected {mem_gb} GB memory")
                    break
    except Exception as e:
        resources["memory_gb"] = 4  # Conservative default
        logger.debug(f"Couldn't read memory info: {str(e)}. Assuming 4GB.")
    
    # Check load average
    try:
        with open('/proc/loadavg', 'r') as f:
            load = f.read().strip().split()
            resources["load_1min"] = float(load[0])
            resources["load_5min"] = float(load[1])
            resources["load_15min"] = float(load[2])
            logger.debug(f"Current load averages: {load[0]} (1min), {load[1]} (5min), {load[2]} (15min)")
    except Exception as e:
        resources["load_1min"] = 1.0  # Default value
        logger.debug(f"Couldn't read load average: {str(e)}")
    
    # Check current SSH connections
    try:
        conn_count = int(subprocess.check_output(
            "netstat -ant | grep ESTABLISHED | grep ':22' | wc -l", 
            shell=True, universal_newlines=True
        ).strip())
        resources["current_connections"] = conn_count
        logger.debug(f"Currently active SSH connections: {conn_count}")
    except Exception as e:
        resources["current_connections"] = 5  # Assume moderate usage
        logger.debug(f"Couldn't check SSH connections: {str(e)}")
    
    # Calculate recommended concurrent node processing based on resources
    if resources.get("cpu_count", 0) > 0:
        # Base node count on CPU cores - allow for some overhead
        node_base = max(2, resources["cpu_count"] - 1)
        
        # Adjust for memory (approximately 300MB per node)
        if "memory_gb" in resources:
            memory_capacity = int(resources["memory_gb"] * 3)  # ~300MB per node
            node_base = min(node_base, memory_capacity)
            
        # Adjust for current load
        if "load_5min" in resources:
            load_factor = resources["load_5min"] / resources["cpu_count"]
            if load_factor > 0.7:  # High load
                node_base = max(2, node_base - 2)
            elif load_factor < 0.3:  # Low load
                node_base = min(node_base + 1, resources["cpu_count"])
                
        # Adjust for existing SSH connections
        if "current_connections" in resources:
            conn_adjust = resources["current_connections"] // 3  # Every 3 connections reduces by 1
            node_base = max(2, node_base - conn_adjust)
            
        # Cap at reasonable maximum and minimum
        recommended = min(node_base, 7)  # Never process more than 7 nodes simultaneously
        recommended = max(recommended, 1)  # Always process at least 1 node
    else:
        recommended = 2  # Default fallback
        
    resources["recommended_parallelism"] = recommended
    logger.info(f"Recommended concurrent nodes: {recommended}")
    
    return resources

class NDNodeManager:
    """Manages Nexus Dashboard nodes and their information"""
    
    def __init__(self, nd_ip, username="rescue-user", password=None):
        """Initialize with the Nexus Dashboard IP"""
        self.nd_ip = nd_ip
        self.username = username
        self.password = password
        self.nodes = []
        self.connection = None
        self.version = None  # Store ND version for version-specific commands
        self.legacy_ssh_mode = False  # Track if we need ssh-rsa compatibility
        
        # SSH Connection Multiplexing Options for 30-50% performance improvement
        # Start without ssh-rsa for security, add it only if needed
        self.ssh_options = [
            "-o StrictHostKeyChecking=no",
            "-o UserKnownHostsFile=/dev/null", 
            "-o LogLevel=ERROR",
            "-o ConnectTimeout=30",
            "-o ControlMaster=auto",
            "-o ControlPath=/tmp/ssh-nd-%r@%h:%p",
            "-o ControlPersist=300"  # Keep connections alive for 5 minutes
        ]
    
    def build_ssh_command(self, node_ip, command, timeout=30):
        """Centralized SSH command builder with connection multiplexing"""
        ssh_opts = self.ssh_options.copy()
        
        # Add legacy SSH options if we've detected the need for them
        if self.legacy_ssh_mode:
            ssh_opts.extend([
                "-o HostKeyAlgorithms=+ssh-rsa",
                "-o PubkeyAcceptedKeyTypes=+ssh-rsa"
            ])
        
        # Note: OpenSSH handles bare IPv6 addresses correctly in user@host format
        # No need to wrap in brackets - this works for both IPv4 and IPv6
        ssh_opts_str = " ".join(ssh_opts)
        # Use SSHPASS environment variable method which is more reliable than -p flag
        # This avoids issues with special characters in passwords and shell escaping
        return f"SSHPASS={shlex.quote(self.password)} sshpass -e ssh {ssh_opts_str} {self.username}@{node_ip} \"{command}\""
    
    def build_scp_command(self, local_file, node_ip, remote_file):
        """Centralized SCP command builder with connection multiplexing"""
        ssh_opts = self.ssh_options.copy()
        
        # Add legacy SSH options if we've detected the need for them
        if self.legacy_ssh_mode:
            ssh_opts.extend([
                "-o HostKeyAlgorithms=+ssh-rsa",
                "-o PubkeyAcceptedKeyTypes=+ssh-rsa"
            ])
        
        # Note: OpenSSH handles bare IPv6 addresses correctly in user@host format
        # No need to wrap in brackets - this works for both IPv4 and IPv6
        ssh_opts_str = " ".join(ssh_opts)
        # Use SSHPASS environment variable method which is more reliable than -p flag
        return f"SSHPASS={shlex.quote(self.password)} sshpass -e scp {ssh_opts_str} {local_file} {self.username}@{node_ip}:{remote_file}"
    
    def enable_legacy_ssh_mode(self):
        """Enable legacy SSH mode (ssh-rsa) for compatibility with older ND versions"""
        if not self.legacy_ssh_mode:
            self.legacy_ssh_mode = True
            logger.warning("Enabling legacy SSH mode (ssh-rsa) for compatibility with older Nexus Dashboard host keys")
            logger.warning("Note: ssh-rsa uses SHA-1 which has known weaknesses. Consider regenerating ND host keys with: ssh-keygen -A")
    
    def _check_crypto_policy(self):
        """Check if system crypto policy is blocking ssh-rsa"""
        rhel_based = False
        try:
            # Try to get current crypto policy (RHEL/CentOS/Fedora/Rocky/Alma)
            result = subprocess.run(
                ['update-crypto-policies', '--show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                rhel_based = True
                policy = result.stdout.strip()
                logger.info(f"Detected RHEL-based crypto policy: {policy}")
                
                if policy in ['DEFAULT', 'FUTURE', 'FIPS']:
                    # These policies block SHA-1/ssh-rsa
                    print(f"\n{FAIL} System crypto policy is blocking ssh-rsa connections")
                    print(f"      Current policy: {policy}")
                    print(f"\n      \033[1mRHEL/CentOS/Fedora 9+ blocks SHA-1 (used by ssh-rsa) at the system level.\033[0m")
                    print(f"      Your Nexus Dashboard requires ssh-rsa, but the crypto policy prevents it.")
                    print(f"\n      To fix this, enable the LEGACY crypto policy:")
                    print(f"\n        \033[1;36msudo update-crypto-policies --set LEGACY\033[0m")
                    print(f"\n      This allows ssh-rsa connections. After changing the policy:")
                    print(f"        1. No service restart needed (change is immediate)")
                    print(f"        2. Run this script again")
                    print(f"\n      Alternative (more secure): Create custom policy for SSH only:")
                    print(f"        sudo update-crypto-policies --set DEFAULT:SHA1")
                    print(f"\n      See: https://access.redhat.com/articles/3642912")
                    
                    logger.error(f"Crypto policy {policy} is blocking ssh-rsa. User must enable LEGACY policy.")
                    return True
            
        except FileNotFoundError:
            logger.debug("update-crypto-policies not found - not a RHEL-based system")
        except Exception as e:
            logger.debug(f"Could not check RHEL crypto policy: {str(e)}")
        
        # If not RHEL-based or policy check didn't trigger, show generic message
        if not rhel_based:
            logger.warning("Legacy SSH failed - may be crypto policy issue on non-RHEL system")
            print(f"\n{FAIL} SSH connection with legacy algorithms failed")
            print(f"\n      \033[1mPossible cause: System crypto policy blocking SHA-1/ssh-rsa\033[0m")
            print(f"      Modern Linux distributions (OpenSSL 3.0+) block weak cryptographic")
            print(f"      algorithms including SHA-1, which is required for ssh-rsa.")
            print(f"\n      Your system appears to be blocking ssh-rsa connections.")
            print(f"\n      For Ubuntu/Debian systems:")
            print(f"        Edit /etc/ssl/openssl.cnf and enable SHA-1 in the [provider_sect]")
            print(f"        See: https://askubuntu.com/q/1233186")
            print(f"\n      For other distributions:")
            print(f"        Check your distribution's documentation for enabling legacy")
            print(f"        cryptographic algorithms or SHA-1 support.")
            print(f"\n      Verify the issue with:")
            print(f"        ssh -vvv -o HostKeyAlgorithms=+ssh-rsa rescue-user@{self.nd_ip}")
            print(f"        (Look for 'error in libcrypto' or similar crypto errors)")
            return True
        
        return False
    
    def connect(self):
        """Connect to the main Nexus Dashboard node with automatic legacy SSH fallback"""
        logger.info(f"Connecting to Nexus Dashboard at {self.nd_ip}")
        
        try:
            # Create a node dict that SSHCommand expects
            node = {"name": "main_node", "ip": self.nd_ip}
            
            # First attempt: Try with modern SSH (secure by default)
            with SSHCommand(self, node, "echo Connected", mask_password=True) as ssh:
                output, error, returncode = ssh.get_results(timeout=10)
                
                if returncode == 0 and "Connected" in output:
                    logger.info(f"Successfully connected to Nexus Dashboard at {self.nd_ip}")
                    return True
                
                # Check if the error is specifically about host key negotiation
                error_is_ssh_negotiation = (
                    "no matching host key type found" in error.lower() or 
                    "their offer: ssh-rsa" in error.lower() or 
                    "unable to negotiate" in error.lower()
                )
                
                # If we got a connection failure, try legacy mode
                if returncode != 0 and (error_is_ssh_negotiation or not error.strip()):
                    if error_is_ssh_negotiation:
                        logger.warning(f"Modern SSH failed due to host key mismatch: {error}")
                    else:
                        logger.warning(f"SSH connection failed (likely ssh-rsa compatibility issue)")
                    
                    logger.info("Attempting connection with legacy ssh-rsa support...")
                    print(f"{WARNING} SSH connection failed - attempting legacy compatibility mode")
                    
                    # Enable legacy mode and retry
                    self.enable_legacy_ssh_mode()
                    
                    # Second attempt: Retry with legacy SSH support
                    with SSHCommand(self, node, "echo Connected", mask_password=True) as ssh_retry:
                        output_retry, error_retry, returncode_retry = ssh_retry.get_results(timeout=10)
                        
                        if returncode_retry == 0 and "Connected" in output_retry:
                            logger.info(f"Successfully connected using legacy SSH mode")
                            print(f"{PASS} Successfully connected using legacy SSH mode")
                            print(f"      Note: ssh-rsa uses SHA-1. Consider regenerating ND host keys")
                            print(f"            with stronger algorithms (ssh-keygen -A on ND)")
                            return True
                        else:
                            # Legacy SSH also failed - check for crypto policy issue
                            logger.error(f"Failed to connect even with legacy SSH: {error_retry}")
                            
                            # Check if this is a crypto policy issue (RHEL 9+)
                            if "error in libcrypto" in error_retry.lower() or not error_retry.strip():
                                crypto_policy_issue = self._check_crypto_policy()
                                if crypto_policy_issue:
                                    return False
                            
                            print(f"{FAIL} Failed to connect even with legacy SSH support")
                            if error_retry.strip():
                                print(f"      Error: {error_retry}")
                            print(f"      Verify:")
                            print(f"        - ND IP is correct: {self.nd_ip}")
                            print(f"        - rescue-user credentials are correct")
                            print(f"        - SSH port 22 is accessible")
                            print(f"      Manual test: ssh -o HostKeyAlgorithms=+ssh-rsa rescue-user@{self.nd_ip}")
                            return False
                else:
                    # Different error - not a host key issue
                    logger.error(f"Failed to connect to Nexus Dashboard: {error}")
                    print(f"{FAIL} Failed to connect to Nexus Dashboard")
                    if error.strip():
                        print(f"      Error: {error}")
                    return False
                    
        except Exception as e:
            logger.exception(f"Error connecting to Nexus Dashboard: {str(e)}")
            print(f"{FAIL} Exception during connection: {str(e)}")
            return False
    
    def disconnect(self):
        """Disconnect from the main Nexus Dashboard node"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def get_techsupport_command(self):
        """
        Get the appropriate tech support command based on ND version.
        For version 4.x and later: 'acs techsupport collect'
        For versions prior to 4.x: 'acs techsupport collect -s system'
        """
        if not self.version:
            logger.warning("ND version not available, using legacy command")
            return "acs techsupport collect -s system"
        
        try:
            # Parse version to get major version number
            version_parts = self.version.split('.')
            
            if len(version_parts) >= 1:
                major = int(version_parts[0])
                
                # Simple logic: version 4.x and later use new command
                if major >= 4:
                    logger.info(f"Version {self.version} >= 4.x, using new command format")
                    return "acs techsupport collect"
                else:
                    logger.info(f"Version {self.version} < 4.x, using legacy command format")
                    return "acs techsupport collect -s system"
            else:
                logger.warning(f"Could not parse version {self.version}, using legacy command")
                return "acs techsupport collect -s system"
                
        except Exception as e:
            logger.warning(f"Error parsing version {self.version}: {str(e)}, using legacy command")
            return "acs techsupport collect -s system"
    
    def check_tmp_space(self, node, tech_support_path):
        """
        Check if /tmp has sufficient space for tech support extraction.
        Returns: (has_space, current_usage_pct, projected_usage_pct, tech_support_size_gb, error_message)
        
        Args:
            node: Node dictionary with 'name' and 'ip'
            tech_support_path: Path to the tech support .tgz file
        
        Returns:
            tuple: (bool, float, float, float, str) - (has_space, current_usage, projected_usage, ts_size_gb, error_msg)
        """
        import subprocess
        
        try:
            # Step 1: Get current /tmp filesystem usage
            logger.info(f"Checking /tmp space on {node['name']}")
            df_cmd = self.build_ssh_command(node['ip'], "df -h /tmp | tail -1")
            process = subprocess.Popen(df_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30)
            
            if process.returncode != 0:
                error_msg = f"Failed to check /tmp space: {stderr.decode('utf-8')}"
                logger.error(f"{node['name']}: {error_msg}")
                return False, 0, 0, 0, error_msg
            
            # Parse df output
            # Example: /dev/mapper/vg--app-lv--app  500G  350G  125G  74% /tmp
            df_output = stdout.decode('utf-8').strip()
            logger.debug(f"{node['name']} df output: {df_output}")
            
            parts = df_output.split()
            if len(parts) < 5:
                error_msg = f"Unexpected df output format: {df_output}"
                logger.error(f"{node['name']}: {error_msg}")
                return False, 0, 0, 0, error_msg
            
            # Extract current usage percentage (column 4, includes % sign)
            current_usage_str = parts[4].rstrip('%')
            try:
                current_usage_pct = float(current_usage_str)
            except ValueError:
                error_msg = f"Failed to parse usage percentage: {parts[4]}"
                logger.error(f"{node['name']}: {error_msg}")
                return False, 0, 0, 0, error_msg
            
            logger.info(f"{node['name']}: Current /tmp usage: {current_usage_pct}%")
            
            # Step 2: Get tech support file size
            size_cmd = self.build_ssh_command(node['ip'], f"stat -c %s {tech_support_path} 2>/dev/null || stat -f %z {tech_support_path}")
            process = subprocess.Popen(size_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30)
            
            if process.returncode != 0:
                error_msg = f"Failed to get tech support file size: {stderr.decode('utf-8')}"
                logger.error(f"{node['name']}: {error_msg}")
                return False, current_usage_pct, current_usage_pct, 0, error_msg
            
            try:
                tech_support_size_bytes = int(stdout.decode('utf-8').strip())
                tech_support_size_gb = tech_support_size_bytes / (1024**3)
                logger.info(f"{node['name']}: Tech support size: {tech_support_size_gb:.2f} GB")
            except ValueError:
                error_msg = f"Failed to parse tech support file size: {stdout.decode('utf-8')}"
                logger.error(f"{node['name']}: {error_msg}")
                return False, current_usage_pct, current_usage_pct, 0, error_msg
            
            # Step 3: Parse total filesystem size and calculate projected usage
            # Extract total size (column 1) - need to handle units (G, T, M, etc.)
            total_size_str = parts[1]
            total_size_gb = self._parse_size_to_gb(total_size_str)
            
            if total_size_gb == 0:
                error_msg = f"Failed to parse total filesystem size: {total_size_str}"
                logger.error(f"{node['name']}: {error_msg}")
                return False, current_usage_pct, current_usage_pct, tech_support_size_gb, error_msg
            
            # Sanity check: Warn about abnormally large tech support files (>10GB is unusual)
            if tech_support_size_gb > 10:
                logger.warning(f"{node['name']}: Tech support file is unusually large ({tech_support_size_gb:.2f} GB). "
                             f"This may indicate an issue with tech support generation (e.g., excessive logs).")
            
            # Calculate current used space in GB
            current_used_gb = (total_size_gb * current_usage_pct) / 100
            
            # Estimate extracted size (compressed .tgz typically expands 2-3x, use 3x to be safe)
            # NOTE: Worker script extracts directly from source (e.g., /techsupport/) to /tmp
            #       WITHOUT copying the .tgz file first, so we only account for extraction space
            estimated_extracted_size_gb = tech_support_size_gb * 3
            
            # Calculate projected usage
            projected_used_gb = current_used_gb + estimated_extracted_size_gb
            projected_usage_pct = (projected_used_gb / total_size_gb) * 100
            
            logger.info(f"{node['name']}: Total /tmp: {total_size_gb:.2f} GB, "
                       f"Currently used: {current_used_gb:.2f} GB ({current_usage_pct}%), "
                       f"Tech support: {tech_support_size_gb:.2f} GB, "
                       f"Est. extracted: {estimated_extracted_size_gb:.2f} GB, "
                       f"Projected usage: {projected_used_gb:.2f} GB ({projected_usage_pct:.1f}%)")
            
            # Check against 70% threshold
            if projected_usage_pct > 70:
                error_msg = (f"Insufficient /tmp space: current {current_usage_pct:.1f}%, "
                           f"projected {projected_usage_pct:.1f}% (would exceed 70% threshold)")
                logger.warning(f"{node['name']}: {error_msg}")
                return False, current_usage_pct, projected_usage_pct, tech_support_size_gb, error_msg
            
            logger.info(f"{node['name']}: Space check PASSED - projected usage {projected_usage_pct:.1f}% is within limits")
            return True, current_usage_pct, projected_usage_pct, tech_support_size_gb, ""
            
        except subprocess.TimeoutExpired:
            error_msg = "Command timeout while checking /tmp space"
            logger.error(f"{node['name']}: {error_msg}")
            return False, 0, 0, 0, error_msg
        except Exception as e:
            error_msg = f"Unexpected error checking /tmp space: {str(e)}"
            logger.exception(f"{node['name']}: {error_msg}")
            return False, 0, 0, 0, error_msg
    
    def _parse_size_to_gb(self, size_str):
        """
        Parse size string with unit (e.g., '500G', '1.5T', '256M') to GB.
        Returns size in GB as float, or 0 if parsing fails.
        """
        try:
            # Extract numeric part and unit
            import re
            match = re.match(r'^([\d.]+)([KMGT]?)$', size_str, re.IGNORECASE)
            if not match:
                logger.warning(f"Failed to parse size string: {size_str}")
                return 0
            
            value = float(match.group(1))
            unit = match.group(2).upper() if match.group(2) else ''
            
            # Convert to GB
            if unit == 'K':
                return value / (1024 * 1024)
            elif unit == 'M':
                return value / 1024
            elif unit == 'G':
                return value
            elif unit == 'T':
                return value * 1024
            else:
                # No unit means bytes
                return value / (1024**3)
        except Exception as e:
            logger.error(f"Error parsing size '{size_str}': {str(e)}")
            return 0
    
    def check_node_disk_space(self, node):
        """
        Check all directory usage on a node and report any over 80%.
        Returns: (is_healthy, over_threshold_dirs, error_message)
        
        Args:
            node: Node dictionary with 'name' and 'ip'
        
        Returns:
            tuple: (bool, list, str) - (is_healthy, list of (dir, usage) tuples, error_msg)
        """
        import subprocess
        
        try:
            logger.info(f"Checking disk space on {node['name']}")
            df_cmd = self.build_ssh_command(node['ip'], "df -h")
            process = subprocess.Popen(df_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30)
            
            if process.returncode != 0:
                error_msg = f"Failed to check disk space: {stderr.decode('utf-8')}"
                logger.error(f"{node['name']}: {error_msg}")
                return False, [], error_msg
            
            # Parse df output
            df_output = stdout.decode('utf-8').strip()
            logger.debug(f"{node['name']} df output:\n{df_output}")
            
            over_threshold = []
            
            for line in df_output.split('\n'):
                # Skip header line and empty lines
                if not line.strip() or line.startswith('Filesystem'):
                    continue
                
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                # Get usage percentage (column 4, includes % sign)
                usage_str = parts[4].rstrip('%')
                try:
                    usage_pct = float(usage_str)
                except ValueError:
                    continue
                
                # Get mount point (last column)
                mount_point = parts[5]
                
                # Skip /tmp/isomount* directories - these are temporary ISO mount points
                # 100% usage is normal when an upgrade ISO is mounted
                if mount_point.startswith('/tmp/isomount'):
                    logger.debug(f"{node['name']}: Skipping {mount_point} (ISO mount point)")
                    continue
                
                # Check if usage >= 80%
                if usage_pct >= 80:
                    over_threshold.append((mount_point, usage_pct))
                    logger.warning(f"{node['name']}: {mount_point} is at {usage_pct}% usage")
            
            if over_threshold:
                # Sort by usage percentage (highest first)
                over_threshold.sort(key=lambda x: x[1], reverse=True)
                error_msg = f"Found {len(over_threshold)} director{'y' if len(over_threshold) == 1 else 'ies'} over 80% usage"
                return False, over_threshold, error_msg
            
            logger.info(f"{node['name']}: All directories under 80% usage threshold")
            return True, [], ""
            
        except subprocess.TimeoutExpired:
            error_msg = "Command timeout while checking disk space"
            logger.error(f"{node['name']}: {error_msg}")
            return False, [], error_msg
        except Exception as e:
            error_msg = f"Unexpected error checking disk space: {str(e)}"
            logger.exception(f"{node['name']}: {error_msg}")
            return False, [], error_msg
    
    def check_eventmonitoring_logs(self, node):
        """
        Check for large eventmonitoring log files (>= 1G).
        This check is only performed for versions below 4.1.1.
        Returns: (is_healthy, large_files, error_message)
        
        Args:
            node: Node dictionary with 'name' and 'ip'
        
        Returns:
            tuple: (bool, list, str) - (is_healthy, list of large file sizes, error_msg)
        """
        import subprocess
        
        try:
            logger.info(f"Checking eventmonitoring logs on {node['name']}")
            
            # Check for files >= 1G in /logs/k8_infra/eventmonitoring
            check_cmd = self.build_ssh_command(node['ip'], "ls -lh /logs/k8_infra/eventmonitoring | awk '{print $5}' | grep -E '^[0-9.]+G'")
            process = subprocess.Popen(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30)
            
            # Parse output
            output = stdout.decode('utf-8').strip()
            
            # If we got output, it means files >= 1G were found
            if output:
                large_files = [line.strip() for line in output.split('\n') if line.strip()]
                error_msg = f"Found {len(large_files)} eventmonitoring log file(s) >= 1G"
                logger.warning(f"{node['name']}: {error_msg}: {', '.join(large_files)}")
                return False, large_files, error_msg
            
            # No large files found
            logger.info(f"{node['name']}: No eventmonitoring log files >= 1G detected")
            return True, [], ""
            
        except subprocess.TimeoutExpired:
            error_msg = "Command timeout while checking eventmonitoring logs"
            logger.error(f"{node['name']}: {error_msg}")
            return False, [], error_msg
        except Exception as e:
            error_msg = f"Unexpected error checking eventmonitoring logs: {str(e)}"
            logger.exception(f"{node['name']}: {error_msg}")
            return False, [], error_msg
    
    def discover_nodes(self):
        """Discover all nodes in the ND cluster using sshpass instead of pexpect"""
        
        try:
            import subprocess
            import shlex
            
            logger.info("Getting Nexus Dashboard version")
            cmd = self.build_ssh_command(self.nd_ip, "acs version")
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            version = None
            if process.returncode == 0:
                output = stdout.decode('utf-8')
                logger.debug("Raw version output: " + output)
                match = re.search(r'Nexus Dashboard\s+(\S+)', output)
                if match:
                    version = match.group(1)
                    self.version = version  # Store version for later use
                    logger.info(f"Nexus Dashboard version: {version}")
                else:
                    version = output.strip()
                    self.version = version  # Store version for later use
                    logger.info(f"Nexus Dashboard version info: {version}")
            else:
                logger.warning("Could not determine Nexus Dashboard version")

            # Try a direct approach for getting node information
            logger.info("Getting Nexus Dashboard node information")
            cmd = self.build_ssh_command(self.nd_ip, "acs show nodes")
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            node_output = ""
            if process.returncode == 0:
                node_output = stdout.decode('utf-8')
            
            # Parse the node output
            logger.debug("Node output to parse: " + node_output)
            self.nodes = self._parse_node_output(node_output)
            
            # If we didn't get any nodes, inform the user instead of using hardcoded values
            if not self.nodes:
                logger.warning("No nodes were discovered from the Nexus Dashboard")
                print(f"{FAIL} Unable to discover nodes from Nexus Dashboard.")
                print("Please check that the node discovery command 'acs show nodes' works correctly.")
                print("If this issue persists, contact Cisco TAC for assistance.")
            
            return self.nodes
                
        except Exception as e:
            logger.error(f"Error discovering nodes: {str(e)}")
            logger.warning("Node discovery failed due to an error")
            print(f"{FAIL} Node discovery failed: {str(e)}")
            print("Please verify your SSH connection is working and you have proper permissions.")
            return []
    
    def _parse_node_output(self, output):
        """Parse the output of 'acs show nodes' command in box-drawing format"""
        nodes = []
        logger.info("Parsing node information...")
        
        # Parse line by line to handle multi-line format
        lines = output.strip().splitlines()
        node_dict = {}
        current_node_name = None
        
        for line in lines:
            # Skip header line
            if "NAME (*=SELF)" in line:
                logger.debug(f"Skipping header line: {line[:50]}...")
                continue
            
            # Skip table border lines (lines that are primarily + and - characters)
            # These look like: +--------------------+----------------+----------+
            stripped = line.strip()
            if stripped and all(c in '+-─═│┌┐└┘├┤┬┴┼' for c in stripped):
                logger.debug(f"Skipping table border line: {line[:50]}...")
                continue
            
            # Skip horizontal separator lines between nodes
            if '──────────' in line or '----------' in line:
                logger.debug(f"Skipping horizontal separator: {line[:50]}...")
                continue
                
            # Check if this line has node data (contains │ or ¦ or any vertical bar-like character)
            # Look for any character that could be a vertical separator (ord 166, 124, 9474, etc.)
            has_separator = False
            delimiter = None
            for char in ['│', '¦', '|']:  # Box drawing, broken bar, pipe
                if char in line:
                    has_separator = True
                    delimiter = char
                    break
            
            if not has_separator:
                # Try to find any vertical bar-like character by checking character codes
                for char in line:
                    if ord(char) in [124, 166, 9474, 9475, 9476]:  # |, ¦, │, ╡, ╢
                        has_separator = True
                        delimiter = char
                        break
            
            if not has_separator:
                logger.debug(f"No separator found in line: {line[:50]}...")
                continue
            
            logger.debug(f"Processing line with delimiter '{delimiter}' (ord={ord(delimiter)}): {line[:60]}...")
            
            # Split by the delimiter
            parts = [p.strip() for p in line.split(delimiter)]
            
            # Filter out empty parts
            parts = [p for p in parts if p]
            
            # Debug: log the parts after filtering
            if parts:
                logger.debug(f"Filtered parts ({len(parts)}): {parts}")
            
            # Skip lines that are all dashes (separator between nodes)
            # These look like: ¦ ------------------ ¦ -------------- ¦ -------- ¦
            if parts and all(all(c == '-' for c in p) for p in parts):
                logger.debug(f"Skipping separator line with all dashes")
                continue
            
            # Need at least 7 parts: name, serial, version, role, datanet, mgmtnet, status
            # OR could be continuation line with just datanet and mgmtnet
            if len(parts) >= 7:
                # This is a full node line with Master role
                node_name = parts[0].replace('*', '').strip()
                serial = parts[1].strip()
                version = parts[2].strip()
                role = parts[3].strip()
                data_network = parts[4].strip()
                mgmt_network = parts[5].strip()
                status = parts[6].strip()
                
                logger.debug(f"Checking node: name={node_name}, role={role}, status={status}")
                
                # Check for Master role (case insensitive)
                if role.lower() == "master":
                    current_node_name = node_name
                    logger.debug(f"Processing Master node: {node_name}")
                    
                    # Create or update node record
                    if node_name not in node_dict:
                        node_dict[node_name] = {
                            "name": node_name,
                            "serial": serial,
                            "version": version,
                            "role": "Master",
                            "datanetwork": [],
                            "mgmtnetwork": [],
                            "status": status
                        }
                        logger.debug(f"Created node entry for: {node_name}")
                    
                    # Collect network addresses (skip placeholders like 0.0.0.0/0 and ::/0)
                    if data_network and data_network not in ["0.0.0.0/0", "::/0"]:
                        node_dict[node_name]["datanetwork"].append(data_network)
                        logger.debug(f"Added data network {data_network} to {node_name}")
                    if mgmt_network and mgmt_network not in ["0.0.0.0/0", "::/0"]:
                        node_dict[node_name]["mgmtnetwork"].append(mgmt_network)
                        logger.debug(f"Added mgmt network {mgmt_network} to {node_name}")
                        
            elif len(parts) >= 2 and current_node_name:
                # This might be a continuation line with just network addresses
                # These lines have empty fields followed by the IP addresses
                # Format: │  │  │  │  │ 2001:6114:114::14/64 │ 2001:420:28e:2023::111:604/64 │  │
                
                # Find non-empty parts that look like IP addresses
                for part in parts:
                    if part and ('.' in part or ':' in part) and '/' in part:
                        # This looks like an IP address with CIDR
                        if ':' in part:
                            # IPv6 - add to mgmt network (typically second column)
                            if part != "0.0.0.0/0" and part != "::/0":
                                # Determine if it's data or mgmt based on position
                                # In the continuation line, data is usually before mgmt
                                part_index = parts.index(part)
                                if part_index == 0 or (len(parts) > 1 and part == parts[0]):
                                    node_dict[current_node_name]["datanetwork"].append(part)
                                else:
                                    node_dict[current_node_name]["mgmtnetwork"].append(part)
                        elif '.' in part:
                            # IPv4
                            if part != "0.0.0.0/0":
                                part_index = parts.index(part)
                                if part_index == 0:
                                    node_dict[current_node_name]["datanetwork"].append(part)
                                else:
                                    node_dict[current_node_name]["mgmtnetwork"].append(part)
        
        # Convert node_dict to list and select primary IPs
        for node_name, node_data in node_dict.items():
            # Prefer IPv6 if available, fallback to IPv4
            # For datanetwork: use first non-placeholder address
            if node_data["datanetwork"]:
                node_data["datanetwork"] = node_data["datanetwork"][0]
            else:
                node_data["datanetwork"] = "unknown"
            
            # For mgmtnetwork: use first non-placeholder address
            if node_data["mgmtnetwork"]:
                node_data["mgmtnetwork"] = node_data["mgmtnetwork"][0]
            else:
                node_data["mgmtnetwork"] = "unknown"
            
            # Extract IP address from mgmt network field
            if '/' in node_data["mgmtnetwork"]:
                node_data["ip"] = node_data["mgmtnetwork"].split('/')[0].strip()
            else:
                node_data["ip"] = node_data["mgmtnetwork"].strip()
            
            nodes.append(node_data)
            logger.debug(f"Added node: {node_data}")
        
        logger.info(f"Parsed {len(nodes)} nodes from output")
        return nodes
    
class TechSupportManager:
    """Manages the selection and generation of tech supports"""
    
    def __init__(self, node_manager):
        """Initialize with the node manager"""
        self.node_manager = node_manager
        self.tech_dir = "/techsupport"  # Standard ND tech support location

    def list_techsupport_files(self, node):
        """List tech support files on a node without user interaction"""
        logger.info(f"Listing tech support files for node {node['name']}")
        
        # Skip inactive nodes
        if node.get('status', '').lower() != 'active':
            logger.warning(f"Skipping tech support listing for inactive node {node['name']}")
            return []
        
        try:
            import subprocess
            import shlex
            
            # Get file listing with a SINGLE command that includes all info we need
            # Format: timestamp size path
            cmd = self.node_manager.build_ssh_command(node['ip'], f"find {self.tech_dir} -name '*.tgz' -type f -printf '%T@ %s %p\\n' | sort -nr")
            
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            output = stdout.decode('utf-8')
            
            # Process the output with all file details at once
            display_info = []
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split(' ', 2)  # Split into timestamp, size, and path
                if len(parts) >= 3:
                    timestamp, size, filepath = parts
                    filename = os.path.basename(filepath)
                    
                    # Format the size in human-readable format
                    size_bytes = int(size)
                    human_size = self._format_size(size_bytes)
                    
                    # Format the timestamp (Unix timestamp) to human-readable date
                    try:
                        date_obj = datetime.fromtimestamp(float(timestamp))
                        date_str = date_obj.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        date_str = "Unknown date"
                    
                    display_info.append({
                        "path": filepath,
                        "name": filename,
                        "size": human_size,
                        "date": date_str
                    })
            
            logger.info(f"Found {len(display_info)} tech support files for node {node['name']}")
            return display_info
                
        except Exception as e:
            logger.exception(f"Error listing tech support files for node {node['name']}: {str(e)}")
            return []

    def select_techsupport(self, node):
        """Select an existing tech support file on a node using optimized sshpass method"""
        logger.info(f"Selecting tech support for node {node['name']}")
        
        print(f"\nChecking tech support files for node {node['name']}...")
        
        try:
            import subprocess
            import shlex
            
            # Get file listing with a SINGLE command that includes all info we need
            # Format: timestamp size path
            cmd = self.node_manager.build_ssh_command(node['ip'], f"find {self.tech_dir} -name '*.tgz' -type f -printf '%T@ %s %p\\n' | sort -nr")
            
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            output = stdout.decode('utf-8')
            
            # Process the output with all file details at once
            display_info = []
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split(' ', 2)  # Split into timestamp, size, and path
                if len(parts) >= 3:
                    timestamp, size, filepath = parts
                    filename = os.path.basename(filepath)
                    
                    # Format the size in human-readable format
                    size_bytes = int(size)
                    human_size = self._format_size(size_bytes)
                    
                    # Format the timestamp (Unix timestamp) to human-readable date
                    try:
                        date_obj = datetime.fromtimestamp(float(timestamp))
                        date_str = date_obj.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        date_str = "Unknown date"
                    
                    display_info.append({
                        "path": filepath,
                        "name": filename,
                        "size": human_size,
                        "date": date_str
                    })
            
            # If we found files, display them to the user
            if display_info:
                # Display files for selection
                print(f"\nTech support files available on {node['name']} ({node['ip']}):\n")
                print()
                for idx, file_info in enumerate(display_info, 1):
                    print(f"{idx}. {file_info['name']}")
                    print(f"   Size: {file_info['size']}, Created: {file_info['date']}")
                
                # Ask user to select a file
                while True:
                    try:
                        range_str = str(len(display_info)) if len(display_info) == 1 else f"1-{len(display_info)}"
                        choice = input(f"\nSelect tech support file for {node['name']} ({range_str}, or 0 to skip): ")
                        if choice == '0':
                            print(f"Skipping node {node['name']}.")
                            return None
                            
                        idx = int(choice) - 1
                        if 0 <= idx < len(display_info):
                            selected_file = display_info[idx]["path"]
                            print(f"Selected: {display_info[idx]['name']}")
                            return selected_file
                        else:
                            print(f"Please enter a number between 0 and {len(display_info)}")
                    except ValueError:
                        print("Please enter a valid number")
            else:
                print(f"\nNo tech support files found on {node['name']}.")
                print(f"Would you like to generate a new tech support? (y/n)")
                choice = input("> ")
                
                if choice.lower() == 'y':
                    return self.generate_techsupport(node)
                else:
                    print(f"Skipping node {node['name']}.")
                    return None
            
        except Exception as e:
            logger.exception(f"Error selecting tech support for node {node['name']}: {str(e)}")
            print(f"Error listing tech support files: {str(e)}")
            print(f"Would you like to generate a new tech support? (y/n)")
            choice = input("> ")
            
            if choice.lower() == 'y':
                return self.generate_techsupport(node)
            else:
                print(f"Skipping node {node['name']}.")
                return None
                
        return None

    def _format_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
    
    def generate_techsupport(self, node):
        """Generate a new tech support file on a node using sshpass instead of pexpect"""
        logger.info(f"Generating tech support for node {node['name']}")
        
        # Skip inactive nodes
        if node.get('status', '').lower() != 'active':
            logger.warning(f"Skipping tech support generation for inactive node {node['name']}")
            return None
        
        try:
            import subprocess
            import shlex
            
            # Get current timestamp before generating tech support
            cmd_timestamp = self.node_manager.build_ssh_command(node['ip'], "date '+%Y-%m-%dT%H-%M-%S'")
            process = subprocess.Popen(cmd_timestamp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to get timestamp on {node['name']}: {stderr.decode('utf-8')}")
            
            pre_command_timestamp = stdout.decode('utf-8').strip()
            logger.info(f"Pre-command timestamp for {node['name']}: {pre_command_timestamp}")
            
            # Generate a new tech support directly in the standard location
            logger.info(f"Generating tech support on {node['name']}...")
            print(f"Starting tech support collection on {node['name']}. This may take several minutes...")
            
            # Get the appropriate tech support command based on ND version
            techsupport_cmd = self.node_manager.get_techsupport_command()
            logger.info(f"Using tech support command: {techsupport_cmd}")
            
            # Command to generate tech support
            cmd = self.node_manager.build_ssh_command(node['ip'], techsupport_cmd)
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=900)  # 15 minute timeout
            
            # Decode output for analysis
            stdout_text = stdout.decode('utf-8')
            stderr_text = stderr.decode('utf-8')
            
            # Check for immediate command failures
            if process.returncode != 0:
                logger.error(f"Tech support command failed on {node['name']} with return code {process.returncode}")
                logger.error(f"Command output: {stdout_text}")
                logger.error(f"Command error: {stderr_text}")
                
                # Check for specific error patterns that indicate immediate failure
                if "unrecognized arguments" in stderr_text or "error: unrecognized arguments" in stdout_text:
                    print(f"{FAIL} Tech support command failed on {node['name']}: Invalid command arguments")
                    print(f"Error: {stderr_text.strip()}")
                    print(f"This indicates the ND version detection may be incorrect or the command syntax has changed.")
                    return None
                elif "usage:" in stderr_text or "usage:" in stdout_text:
                    print(f"{FAIL} Tech support command failed on {node['name']}: Command usage error")
                    print(f"Error: {stderr_text.strip()}")
                    return None
                else:
                    print(f"{FAIL} Tech support command failed on {node['name']}: {stderr_text.strip()}")
                    return None
            
            # Check for known success indicators in the output
            if "Started: TS collection" in stdout_text or "TS collection" in stdout_text:
                logger.info(f"Tech support command executed successfully on {node['name']}")
                print(f"Tech support collection started successfully on {node['name']}")
                logger.debug(f"Tech support success output: {stdout_text.strip()}")
            elif stdout_text.strip():
                # If there's output but no clear success indicator, log it for debugging
                logger.warning(f"Tech support command output on {node['name']}: {stdout_text.strip()}")
                print(f"Tech support command executed on {node['name']}, output: {stdout_text.strip()}")
                print(f"Checking for file generation...")
            else:
                # No output at all might indicate a problem
                logger.warning(f"No output from tech support command on {node['name']}")
                print(f"Tech support command executed on {node['name']} with no output, checking for file generation...")
            
            # Wait and retry loop to wait for the tech support to be generated
            # Monitor file size growth - continue waiting as long as the file is actively growing
            retry_interval = 30  # Check for new files every 30 seconds
            stale_check_interval = 5  # Once size stops increasing, verify every 5 seconds
            max_stale_checks = 3  # Maximum consecutive checks with no size increase (at 5-second intervals = 15 seconds total)
            
            logger.info(f"Waiting for tech support generation to complete on {node['name']}...")
            # Don't print to console - we'll show status when file is detected
            
            # Record all existing tech support files to detect new ones
            cmd_existing = self.node_manager.build_ssh_command(node['ip'], f"find {self.tech_dir} -name '*{node['name']}.tgz' -type f -printf '%T@ %p\\n'")
            process = subprocess.Popen(cmd_existing, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            existing_tech_support_files = []
            if process.returncode == 0:
                for line in stdout.decode('utf-8').strip().split('\n'):
                    if line.strip():
                        parts = line.split(' ', 1)
                        if len(parts) == 2:
                            _, filepath = parts
                            existing_tech_support_files.append(filepath)
                            logger.debug(f"Existing tech support file: {filepath}")
            
            # Now wait and look for a new file with timestamp AFTER our pre_command_timestamp
            found_tech_support = None
            no_processes_detected = False
            tracked_file = None  # Track which file we're monitoring for size changes
            last_size = 0
            stale_count = 0  # Count consecutive checks with no size increase
            retry_number = 0
            
            while True:
                # Always wait the full retry_interval (30 seconds) between checks
                # We'll do rapid verification at 5-second intervals only when size stops increasing
                time.sleep(retry_interval)
                retry_number += 1
                
                logger.info(f"Tech support check attempt {retry_number} for {node['name']}")
                # Don't print status here - we'll print more meaningful status in the loop below
                
                # On first few retries, check if tech support processes are actually running
                # This helps detect early if the command failed to start properly
                if retry_number <= 3 and not no_processes_detected:  # Check on first 3 retries (first 1.5 minutes)
                    logger.debug(f"Checking if tech support processes are running on {node['name']}")
                    cmd_check_processes = self.node_manager.build_ssh_command(node['ip'], "ps aux | grep -i techsupport | grep -v grep || echo 'no_processes'")
                    process = subprocess.Popen(cmd_check_processes, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout_ps, stderr_ps = process.communicate()
                    
                    if process.returncode == 0:
                        ps_output = stdout_ps.decode('utf-8').strip()
                        if "no_processes" in ps_output:
                            if not no_processes_detected:
                                logger.warning(f"No tech support processes running on {node['name']} (retry {retry_number})")
                                no_processes_detected = True
                        else:
                            logger.debug(f"Tech support processes found running on {node['name']}")
                            no_processes_detected = False
                
                # Get the current date part for identifying today's tech supports
                cmd_date = self.node_manager.build_ssh_command(node['ip'], "date '+%Y-%m-%d'")
                process = subprocess.Popen(cmd_date, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    logger.warning(f"Failed to get current date on {node['name']} (retry {retry_number})")
                    continue
                    
                current_date = stdout.decode('utf-8').strip()
                date_prefix = f"{current_date}T"
                
                # Determine the tech support file pattern based on ND version
                # Version 4.x and later use "all-ts", earlier versions use "system-ts"
                techsupport_cmd = self.node_manager.get_techsupport_command()
                if "collect -s system" in techsupport_cmd:
                    ts_pattern = f"*-system-ts-{node['name']}.tgz"
                    ts_type = "system-ts"
                else:
                    ts_pattern = f"*-all-ts-{node['name']}.tgz"
                    ts_type = "all-ts"
                
                # List all tech support files, sorted by timestamp (newest first)
                cmd = self.node_manager.build_ssh_command(node['ip'], f"find {self.tech_dir} -name '{ts_pattern}' -type f -printf '%T@ %s %p\\n' | sort -nr")
                logger.debug(f"Looking for tech support files with pattern: {ts_pattern}")
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode != 0 or not stdout:
                    logger.warning(f"Failed to list tech support files on {node['name']} (retry {retry_number})")
                    continue
                
                ts_files = stdout.decode('utf-8').strip().split('\n')
                
                # First look for a tech support that is NOT in our existing list
                # AND has a timestamp in the filename AFTER our pre_command_timestamp
                current_check_size = 0  # Track the size of the file we're checking this iteration
                for ts_file in ts_files:
                    if not ts_file.strip():
                        continue
                        
                    parts = ts_file.split(' ', 2)
                    if len(parts) < 3:
                        continue
                    
                    # Parse timestamp, size, and filepath
                    _, size, filepath = parts
                    size_bytes = int(size)
                    
                    # Skip files that were in our existing list 
                    if filepath in existing_tech_support_files:
                        logger.debug(f"Skipping existing tech support: {filepath}")
                        continue
                    
                    filename = os.path.basename(filepath)
                    logger.debug(f"Found potential new tech support: {filename}, size: {size_bytes} bytes")
                    
                    # Extract timestamp from filename - format like 2025-05-04T21-09-06Z-system-ts-nd2.tgz or 2025-05-04T21-09-06Z-all-ts-nd2.tgz
                    if date_prefix in filename and (f'-{ts_type}-' in filename):
                        # Extract just the timestamp part before -system-ts- or -all-ts-
                        ts_part = filename.split(f'-{ts_type}-')[0]
                        
                        # Handle the Z part if present
                        if 'Z' in ts_part:
                            ts_part = ts_part.split('Z')[0]
                        
                        # Format pre_command_timestamp to match the format in the filename (remove seconds)
                        pre_timestamp_nosec = pre_command_timestamp.rsplit('-', 1)[0] if pre_command_timestamp else ""
                        
                        logger.debug(f"Comparing ts_part: {ts_part} with pre_timestamp: {pre_timestamp_nosec}")
                        
                        # Explicitly compare the timestamp string lexicographically
                        if pre_timestamp_nosec and ts_part > pre_timestamp_nosec:
                            logger.info(f"Found new tech support with timestamp after command: {filename}")
                            
                            # Track this file for size monitoring
                            if tracked_file is None:
                                tracked_file = filepath
                                last_size = size_bytes
                                logger.info(f"Started tracking tech support file: {filepath}, initial size: {size_bytes} bytes")
                                print(f"Found tech support file being generated on {node['name']}, monitoring for completion...")
                                # Skip size comparison on first detection - we need to wait for next check
                                break
                            
                            # Update current check size
                            current_check_size = size_bytes
                            
                            # If this is the file we're tracking, check if size has grown
                            if tracked_file == filepath:
                                if size_bytes > last_size:
                                    # Size is increasing - file is still being generated
                                    size_increase = size_bytes - last_size
                                    logger.info(f"Tech support file size increased from {last_size} to {size_bytes} bytes (+{size_increase} bytes)")
                                    print(f"Tech support still generating on {node['name']}: {size_bytes / (1024**3):.2f} GB (+{size_increase / (1024**2):.1f} MB)...")
                                    last_size = size_bytes
                                    stale_count = 0  # Reset stale counter since size increased
                                elif size_bytes == last_size:
                                    # Size hasn't changed - perform rapid verification immediately
                                    logger.info(f"Tech support file size unchanged at {size_bytes} bytes, performing rapid verification")
                                    print(f"File size stable on {node['name']}, performing verification checks...")
                                    
                                    # Perform 3 rapid verification checks at 5-second intervals (15 seconds total)
                                    verification_stable = True
                                    for verify_check in range(max_stale_checks):
                                        time.sleep(stale_check_interval)
                                        
                                        cmd_size = self.node_manager.build_ssh_command(node['ip'], f"stat -c %s {filepath}")
                                        process = subprocess.Popen(cmd_size, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                        stdout, stderr = process.communicate()
                                        
                                        if process.returncode != 0:
                                            logger.warning(f"Failed to get file size for verification check {verify_check + 1} on {filepath}")
                                            verification_stable = False
                                            break
                                        
                                        try:
                                            verify_size = int(stdout.decode('utf-8').strip())
                                            logger.info(f"Verification check {verify_check + 1}/{max_stale_checks}: size = {verify_size} bytes")
                                            
                                            if verify_size != size_bytes:
                                                # Size changed during verification - still generating
                                                logger.info(f"Size changed during verification ({size_bytes} -> {verify_size}), file still generating")
                                                print(f"Tech support still generating on {node['name']}, continuing to monitor...")
                                                last_size = verify_size
                                                stale_count = 0
                                                verification_stable = False
                                                break
                                        except (ValueError, TypeError) as e:
                                            logger.warning(f"Error parsing file size during verification: {str(e)}")
                                            verification_stable = False
                                            break
                                    
                                    # If all 3 verification checks showed stable size, file is complete
                                    if verification_stable:
                                        logger.info(f"Tech support file confirmed complete after {max_stale_checks} consecutive stable checks at {stale_check_interval}-second intervals")
                                        print(f"Tech support generation confirmed complete on {node['name']}")
                                        found_tech_support = filepath
                                        break
                                    # If verification failed (size changed), we'll continue the outer loop for next 30-second check
                            break  # Exit the for loop since we found our tracked file
                
                # If we found a new tech support with proper timestamp and stable size, we're done
                if found_tech_support:
                    break
                
                # Check if we should give up (only if no file was found at all after initial retries)
                if tracked_file is None and retry_number >= 3:
                    # No file appeared after 3 retries (1.5 minutes), likely a failure
                    logger.error(f"No new tech support file appeared on {node['name']} after {retry_number} checks")
                    print(f"{FAIL} Tech support generation failed on {node['name']} - no new file detected.")
                    print(f"No new tech support with timestamp after {pre_command_timestamp} was found.")
                    print(f"")
                    if no_processes_detected:
                        print(f"⚠️  WARNING: No tech support processes were detected running on the node.")
                    print(f"This usually indicates one of the following:")
                    print(f"  1. The tech support command failed due to invalid arguments")
                    print(f"  2. The tech support command is not supported on this ND version")
                    print(f"  3. There is insufficient disk space to generate the tech support")
                    print(f"")
                    print(f"To debug this issue:")
                    print(f"  1. SSH to {node['name']} and manually run: {techsupport_cmd}")
                    print(f"  2. Check disk space with: df -h")
                    print(f"  3. Check for running processes with: ps aux | grep techsupport")
                    return None
                
                # Note: We no longer need a separate stale check here because we perform
                # immediate rapid verification when size stops increasing (handled in the file checking loop above)
                    
                # Log elapsed time for debugging but don't print to console (too verbose)
                elapsed_time = retry_number * retry_interval / 60
                if tracked_file:
                    logger.debug(f"Tech support generation in progress on {node['name']} ({elapsed_time:.1f} minutes elapsed)")
                else:
                    logger.debug(f"Waiting for tech support file to appear on {node['name']} ({elapsed_time:.1f} minutes elapsed)")
            
            # We should only get here if found_tech_support is set
            if not found_tech_support:
                logger.error(f"Unexpected state: exited monitoring loop without finding tech support on {node['name']}")
                return None
            
            # Calculate total elapsed time
            elapsed_time = retry_number * retry_interval / 60
            
            # Verify the tech support exists and has non-zero size
            cmd = self.node_manager.build_ssh_command(node['ip'], f"test -s {found_tech_support} && echo 'exists' || echo 'not found'")
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if "exists" in stdout.decode('utf-8'):
                print(f"{PASS} Tech support generated on {node['name']}: {found_tech_support}")
                logger.info(f"Generation took approximately {elapsed_time:.1f} minutes")
                
                # Final check - validate the tech support file by looking at its structure
                cmd_validate = self.node_manager.build_ssh_command(node['ip'], f"gzip -t {found_tech_support} && echo 'valid' || echo 'invalid'")
                process = subprocess.Popen(cmd_validate, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if "valid" in stdout.decode('utf-8'):
                    logger.info(f"Tech support file validated successfully")
                    return found_tech_support
                else:
                    logger.error(f"Tech support file validation failed: {stderr.decode('utf-8')}")
                    print(f"Tech support file appears to be corrupt on {node['name']}. Will try to generate a new one.")
                    return None
            else:
                logger.error(f"Tech support file exists but is empty or not readable: {found_tech_support}")
                return None
                    
        except Exception as e:
            logger.exception(f"Error generating tech support on node {node['name']}: {str(e)}")
            return None

class WorkerScriptManager:
    """Manages the deployment and execution of worker scripts on nodes"""
    
    def __init__(self, node_manager):
        """Initialize with the node manager"""
        self.node_manager = node_manager
        self.base_dir = "/tmp/ndpreupgradecheck"
        self.results_dir = os.path.join(os.getcwd(), "final-results")
        
    def deploy_worker_script(self, node, worker_script_content, stagger_delay=0):
        """Optimized worker script deployment - avoids argument length limits"""
        import subprocess
        import shlex
        import time
        import tempfile
        
        # Skip inactive nodes
        if node.get('status', '').lower() != 'active':
            logger.warning(f"Skipping worker script deployment for inactive node {node['name']}")
            return False
        
        # Add stagger delay to spread out parallel SSH connections
        if stagger_delay > 0:
            time.sleep(stagger_delay)
            
        logger.info(f"Deploying worker script to node {node['name']} with optimized single-command approach...")
        
        try:
            script_path = f"{self.base_dir}/nd_worker.py"
            
            # Helper function to execute SSH command with retry logic
            def execute_ssh_with_retry(cmd, description, retries=3, delay=2):
                for attempt in range(retries):
                    if attempt > 0:
                        logger.debug(f"Retry {attempt}/{retries-1} for: {description}")
                        time.sleep(delay * attempt)  # Increasing delay
                    
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0:
                        return True, stdout.decode('utf-8'), stderr.decode('utf-8')
                    elif "Connection refused" in stderr.decode('utf-8'):
                        logger.debug(f"Connection refused on attempt {attempt + 1}, retrying...")
                        continue
                    else:
                        # Non-connection error, don't retry
                        return False, stdout.decode('utf-8'), stderr.decode('utf-8')
                
                return False, stdout.decode('utf-8'), stderr.decode('utf-8')
            
            # Use SCP for file transfer then SSH for setup - avoids argument length limits
            # Create local temporary file for the worker script
            with MultipleFileManager() as file_manager:
                temp_path = tempfile.mktemp()
                temp_file = file_manager.open(temp_path, 'w')
                temp_file.write(worker_script_content)
                temp_file.flush()
                temp_file.close()
                
                # Step 1: Create directories first
                setup_cmd = f"mkdir -p {self.base_dir} {self.base_dir}/{node['name']} && chmod 755 {self.base_dir} {self.base_dir}/{node['name']}"
                ssh_cmd = self.node_manager.build_ssh_command(node['ip'], setup_cmd)
                
                logger.debug(f"Creating directories on {node['name']}")
                success, stdout, stderr = execute_ssh_with_retry(ssh_cmd, "create directories")
                
                if not success:
                    logger.warning(f"Directory creation failed for {node['name']}: {stderr}")
                    raise Exception(f"Directory setup failed: {stderr}")
                
                # Step 2: Transfer file using SCP with connection multiplexing
                logger.debug(f"Transferring worker script to {node['name']} using optimized SCP")
                scp_cmd = self.node_manager.build_scp_command(temp_path, node['ip'], script_path)
                success, stdout, stderr = execute_ssh_with_retry(scp_cmd, "transfer script")
                
                if not success:
                    logger.debug(f"SCP transfer failed for {node['name']}: {stderr}")
                    raise Exception(f"File transfer failed: {stderr}")
                
                # Step 3: Set permissions and verify in single command
                verify_cmd = f"chmod +x {script_path} && test -f {script_path} && echo 'deployment-complete'"
                ssh_cmd = self.node_manager.build_ssh_command(node['ip'], verify_cmd)
                
                logger.debug(f"Setting permissions and verifying deployment on {node['name']}")
                success, stdout, stderr = execute_ssh_with_retry(ssh_cmd, "finalize deployment")
                
                if success and "deployment-complete" in stdout:
                    logger.info(f"Worker script successfully deployed to node {node['name']} using optimized method")
                    return script_path
                else:
                    logger.warning(f"Deployment verification failed for {node['name']}: {stderr}")
                    raise Exception(f"Deployment verification failed: {stderr}")
                    
        except Exception as e:
            logger.debug(f"Error in optimized deployment for node {node['name']}: {str(e)}")
            # Fall back to original method
            return self._deploy_worker_script_fallback(node, worker_script_content, stagger_delay)
    
    def _deploy_worker_script_fallback(self, node, worker_script_content, stagger_delay=0):
        """Fallback method using the original multi-step deployment approach"""
        import subprocess
        import shlex
        import time
        
        logger.info(f"Using fallback deployment method for node {node['name']}")
        script_path = f"{self.base_dir}/nd_worker.py"
        
        try:
            # Helper function to execute SSH command with retry logic
            def execute_ssh_with_retry(cmd, description, retries=3, delay=2):
                for attempt in range(retries):
                    if attempt > 0:
                        logger.debug(f"Retry {attempt}/{retries-1} for: {description}")
                        time.sleep(delay * attempt)  # Increasing delay
                    
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0:
                        return True, stdout.decode('utf-8'), stderr.decode('utf-8')
                    elif "Connection refused" in stderr.decode('utf-8'):
                        logger.debug(f"Connection refused on attempt {attempt + 1}, retrying...")
                        continue
                    else:
                        # Non-connection error, don't retry
                        return False, stdout.decode('utf-8'), stderr.decode('utf-8')
                
                return False, stdout.decode('utf-8'), stderr.decode('utf-8')
            
            # Step 1: Create base directory using centralized command builder
            logger.debug(f"Creating base directory for {node['name']}")
            cmd1 = self.node_manager.build_ssh_command(node['ip'], f"mkdir -p {self.base_dir} && chmod 755 {self.base_dir}")
            success, stdout, stderr = execute_ssh_with_retry(cmd1, "create base directory")
            
            if not success:
                logger.error(f"Failed to create base directory on node {node['name']}: {stderr}")
                return False
            
            # Add delay before next SSH connection
            time.sleep(1)
            
            # Step 2: Create node-specific directory using centralized command builder
            logger.debug(f"Creating node-specific directory for {node['name']}")
            node_dir = f"{self.base_dir}/{node['name']}"
            cmd2 = self.node_manager.build_ssh_command(node['ip'], f"mkdir -p {node_dir} && chmod 755 {node_dir}")
            success, stdout, stderr = execute_ssh_with_retry(cmd2, "create node directory")
            
            if not success:
                logger.error(f"Failed to create node directory on {node['name']}: {stderr}")
                return False
            
            # Add delay before SCP
            time.sleep(1)
            
            # Use MultipleFileManager to manage file resources
            with MultipleFileManager() as file_manager:
                # Write script content to a local temp file
                temp_path = tempfile.mktemp()
                temp_file = file_manager.open(temp_path, 'w')
                temp_file.write(worker_script_content)
                temp_file.flush()
                temp_file.close()  # Close file for reading by SCP
                
                # Step 3: Transfer file using optimized SCP with connection multiplexing
                logger.debug(f"Transferring worker script to {node['name']} using SCP")
                scp_cmd = self.node_manager.build_scp_command(temp_path, node['ip'], script_path)
                success, stdout, stderr = execute_ssh_with_retry(scp_cmd, "transfer file")
                
                if not success:
                    error = stderr
                    logger.debug(f"Failed to transfer script to node {node['name']} using SCP: {error}")
                    
                    # Fall back to alternative method using cat
                    logger.debug(f"Falling back to cat method for {node['name']}")
                    time.sleep(1)  # Delay before fallback
                    
                    # Re-open the temp file for reading
                    temp_file = file_manager.open(temp_path, 'r')
                    script_content = temp_file.read()
                    temp_file.close()
                    
                    # Write script content to a safe temp file without newlines escaping
                    safe_temp_path = tempfile.mktemp()
                    safe_temp_file = file_manager.open(safe_temp_path, 'w')
                    safe_temp_file.write(script_content)
                    safe_temp_file.close()
                    
                    cat_cmd = f"cat {safe_temp_path} | {self.node_manager.build_ssh_command(node['ip'], f'cat > {script_path}')}"
                    success, stdout, stderr = execute_ssh_with_retry(cat_cmd, "transfer file using cat")
                    
                    if not success:
                        logger.error(f"Failed to transfer script using cat: {stderr}")
                        return False
                
                # Add delay before next SSH
                time.sleep(1)
                
                # Step 4: Make script executable with centralized command builder
                logger.debug(f"Making script executable on {node['name']}")
                chmod_cmd = self.node_manager.build_ssh_command(node['ip'], f"chmod +x {script_path}")
                success, stdout, stderr = execute_ssh_with_retry(chmod_cmd, "make executable")
                
                if not success:
                    logger.error(f"Failed to make script executable on node {node['name']}: {stderr}")
                    return False
                
                # Add delay before verification
                time.sleep(1)
                
                # Step 5: Verify script exists with centralized command builder
                logger.debug(f"Verifying script exists on {node['name']}")
                verify_cmd = self.node_manager.build_ssh_command(node['ip'], f"test -f {script_path} && echo 'exists' || echo 'missing'")
                success, stdout, stderr = execute_ssh_with_retry(verify_cmd, "verify script exists")
                
                if success and "exists" in stdout:
                    logger.info(f"Worker script successfully deployed to node {node['name']} via fallback method")
                    return script_path
                else:
                    logger.error(f"Script verification failed on {node['name']}: {stderr}")
                    return False
                    
        except Exception as e:
            logger.exception(f"Error in fallback deployment for node {node['name']}: {str(e)}")
            return False
    
    def _execute_ssh_command(self, node, command, mask_password=True):
        """Execute an SSH command on a node using centralized command builder"""
        try:
            # Use centralized SSH command builder with connection multiplexing
            full_cmd = self.node_manager.build_ssh_command(node['ip'], command)
            
            # Create masked version for logs
            if mask_password:
                masked_cmd = full_cmd.replace(self.node_manager.password, "********")
                logger.debug(f"Executing SSH command (masked): {masked_cmd}")
            
            # Execute the command
            process = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # Return the output
            return stdout.decode('utf-8'), stderr.decode('utf-8'), process.returncode
        except Exception as e:
            logger.error(f"Error executing SSH command: {str(e)}")
            return "", str(e), 1

    def check_python_availability(self, node):
        """Check which Python interpreters are available on the node"""
        logger.debug(f"Checking Python availability on node {node['name']}")
        
        python_interpreters = ['python3', 'python', 'python2']
        available_interpreters = []
        
        for interpreter in python_interpreters:
            try:
                # Use centralized SSH command builder
                cmd = self.node_manager.build_ssh_command(node['ip'], f"which {interpreter} && {interpreter} --version")
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    output = stdout.decode('utf-8').strip()
                    available_interpreters.append({
                        'interpreter': interpreter,
                        'path': output.split('\n')[0] if output else 'unknown',
                        'version': output.split('\n')[1] if '\n' in output else 'unknown'
                    })
                    logger.debug(f"Found {interpreter} on {node['name']}: {output}")
                else:
                    logger.debug(f"{interpreter} not found on {node['name']}")
            except Exception as e:
                logger.debug(f"Error checking {interpreter} on {node['name']}: {str(e)}")
        
        return available_interpreters

    def execute_worker_script(self, node, script_path, tech_support_path, operation, stagger_delay=0):
        """Execute the worker script on a node with SSH connection delays and retry logic"""
        import subprocess
        import shlex
        import time
        
        # Skip inactive nodes
        if node.get('status', '').lower() != 'active':
            logger.warning(f"Skipping worker script execution for inactive node {node['name']}")
            return None
        
        # Add stagger delay to spread out parallel SSH connections
        if stagger_delay > 0:
            time.sleep(stagger_delay)
            
        logger.info(f"Executing worker script on node {node['name']} with connection delays...")
        
        try:
            
            # Create a masked version of the password for logging
            masked_password = '********' if self.node_manager.password else ''
            
            # Helper function to execute SSH command with retry logic
            def execute_ssh_with_retry(cmd, description, retries=3, delay=2):
                for attempt in range(retries):
                    if attempt > 0:
                        logger.debug(f"Retry {attempt}/{retries-1} for: {description}")
                        time.sleep(delay * attempt)  # Increasing delay
                    
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0:
                        return True, stdout.decode('utf-8'), stderr.decode('utf-8')
                    elif "Connection refused" in stderr.decode('utf-8'):
                        logger.debug(f"Connection refused on attempt {attempt + 1}, retrying...")
                        continue
                    else:
                        # Non-connection error, don't retry
                        return False, stdout.decode('utf-8'), stderr.decode('utf-8')
                
                return False, stdout.decode('utf-8'), stderr.decode('utf-8')
            
            # Step 1: Check which Python interpreters are available
            logger.debug(f"Checking Python availability on {node['name']}")
            available_interpreters = self.check_python_availability(node)
            if not available_interpreters:
                logger.error(f"No Python interpreters found on node {node['name']}")
                return False
            
            # Log available interpreters for debugging
            for interp in available_interpreters:
                logger.info(f"Found Python interpreter on {node['name']}: {interp['interpreter']} at {interp['path']} ({interp['version']})")
            
            # Choose the best Python interpreter (prefer python3, then python, then python2)
            python_cmd = None
            for preferred in ['python3', 'python', 'python2']:
                for interp in available_interpreters:
                    if interp['interpreter'] == preferred:
                        python_cmd = preferred
                        logger.info(f"Selected {python_cmd} for execution on {node['name']}")
                        break
                if python_cmd:
                    break
            
            if not python_cmd:
                logger.error(f"No suitable Python interpreter found on node {node['name']}")
                return False
            
            # Add delay before next SSH operation
            time.sleep(1)
            
            # Step 2: Verify the tech support path exists before trying to process it
            logger.debug(f"Verifying tech support file on {node['name']}")
            verify_cmd = self.node_manager.build_ssh_command(node['ip'], f"test -f {tech_support_path} && echo 'exists' || echo 'not found'") + " 2>/dev/null"
            success, stdout, stderr = execute_ssh_with_retry(verify_cmd, "verify tech support file")
            
            if not success or "not found" in stdout:
                logger.error(f"Tech support file not found on node {node['name']}: {tech_support_path}")
                return False
            
            # Add delay before next SSH operation
            time.sleep(1)
            
            # Step 3: Create initial status file with proper JSON format
            logger.debug(f"Setting up initial status on {node['name']}")
            init_status = json.dumps({
                "status": "initializing", 
                "current_operation": "Starting worker script", 
                "progress": 0
            })
            
            init_status_cmd = self.node_manager.build_ssh_command(node['ip'], f"mkdir -p {self.base_dir} && echo '{init_status}' > {self.base_dir}/{node['name']}_status.json") + " 2>/dev/null"
            success, stdout, stderr = execute_ssh_with_retry(init_status_cmd, "setup initial status")
            
            if not success:
                logger.warning(f"Failed to set initial status on {node['name']}: {stderr}")
            
            # Add delay before Python test
            time.sleep(1)
            
            # Step 4: Test Python interpreter with retry
            logger.debug(f"Testing Python execution on {node['name']}")
            nd_version = self.node_manager.version or "unknown"
            test_cmd = self.node_manager.build_ssh_command(node['ip'], f"cd {self.base_dir} && {python_cmd} -c 'import sys; print(sys.version)' && echo 'Python test successful'") + " 2>&1"
            success, test_output, stderr = execute_ssh_with_retry(test_cmd, "test Python interpreter")
            
            if not success or "Python test successful" not in test_output:
                logger.error(f"Python interpreter test failed on {node['name']}: {test_output}")
                return False
            
            # Add delay before worker script execution
            time.sleep(1)
            
            # Step 5: Execute the worker script with retry logic
            logger.debug(f"Executing worker script on {node['name']}")
            cmd = self.node_manager.build_ssh_command(node['ip'], f"cd {self.base_dir} && echo '[Starting worker script at $(date)]' > {node['name']}_output.log 2>&1 && echo 'Executing: {python_cmd} -u {script_path} {operation} {tech_support_path} {nd_version}' >> {node['name']}_output.log 2>&1 && nohup {python_cmd} -u {script_path} {operation} {tech_support_path} {nd_version} >> {node['name']}_output.log 2>&1 & echo $!")
            success, stdout, stderr = execute_ssh_with_retry(cmd, "execute worker script")
            
            if not success:
                logger.error(f"Failed to execute worker script on node {node['name']}: {stderr}")
                
                # Try to get more detailed error information with retry
                time.sleep(1)
                detailed_error_cmd = self.node_manager.build_ssh_command(node['ip'], f"cd {self.base_dir} && cat {node['name']}_output.log 2>/dev/null || echo 'No output log found'")
                success2, detailed_output, stderr2 = execute_ssh_with_retry(detailed_error_cmd, "get error details")
                
                if success2:
                    logger.error(f"Detailed error output for {node['name']}: {detailed_output}")
                return False
            
            # Get the process ID if available
            process_id = stdout.strip()
            if process_id and process_id.isdigit():
                logger.info(f"Worker script started on {node['name']} with PID {process_id}")
            else:
                logger.warning(f"Could not determine process ID for worker script on {node['name']}: {stdout}")
            
            # Add delay before checking log output
            time.sleep(3)
            
            # Step 6: Check the log output for any immediate issues with retry
            logger.debug(f"Checking initial log output on {node['name']}")
            check_log_cmd = self.node_manager.build_ssh_command(node['ip'], f"tail -30 {self.base_dir}/{node['name']}_output.log || echo 'No log output yet'") + " 2>/dev/null"
            success, log_output, stderr = execute_ssh_with_retry(check_log_cmd, "check log output")
            
            if success:
                logger.debug(f"Initial log output for {node['name']}: {log_output}")
                
                # Check for immediate errors in the log
                if "Error" in log_output or "ERROR" in log_output or "Traceback" in log_output:
                    logger.error(f"Detected error in initial log output for {node['name']}: {log_output}")
                    return False
                elif "Starting Nexus Dashboard Pre-upgrade Validation" in log_output:
                    logger.info(f"Worker script successfully started on {node['name']}")
                else:
                    logger.warning(f"Worker script may not have started properly on {node['name']} - log: {log_output}")
            else:
                logger.warning(f"Could not check log output on {node['name']}: {stderr}")
            
            logger.info(f"Worker script executed on node {node['name']}")
            return True
            
        except Exception as e:
            logger.exception(f"Error executing worker script on node {node['name']}: {str(e)}")
            return False
    
    def check_worker_status(self, node):
        """Optimized status checking - 60% reduction in monitoring overhead with single compound command"""
        logger.debug(f"Checking worker status on node {node['name']} with optimized single-command approach")
        
        # Check if the node exists and has a valid IP
        if not node or "ip" not in node:
            logger.error(f"Invalid node information for status check")
            return {"status": "unknown", "current_operation": "Invalid node information", "progress": 0}
        
        try:
            log_file = f"{self.base_dir}/{node['name']}_output.log"
            results_file = f"{self.base_dir}/{node['name']}_results.json"
            status_file = f"{self.base_dir}/{node['name']}_status.json"
            logs_tgz = f"{self.base_dir}/{node['name']}/logs.tgz"
            
            # Single compound SSH command to get all status information at once
            # This replaces 6+ separate SSH calls with just 1
            compound_cmd = f"""
            echo "=== STATUS_CHECK_START ===" &&
            
            # Check for completion markers
            if test -f {log_file}; then
                if grep -E 'Validation complete|All operations completed|status: complete' {log_file} > /dev/null 2>&1; then
                    echo "STATUS:complete"
                fi
            fi &&
            
            # Check for results file (definitive completion indicator)
            if test -f {results_file}; then
                echo "RESULTS_FILE:exists"
            fi &&
            
            # Check for fatal tar extraction errors
            if test -f {log_file}; then
                if grep -E 'Error is not recoverable: exiting now|not recoverable|tar: Error' {log_file} > /dev/null 2>&1; then
                    echo "TAR_ERROR:detected"
                    echo "TAR_ERROR_DETAILS:"
                    grep -E 'Error is not recoverable: exiting now|not recoverable|tar: Error' {log_file} | tail -3
                fi
            fi &&
            
            # Check for script errors
            if test -f {log_file}; then
                if grep -E 'Error:|Traceback|SyntaxError|NameError|TypeError|ValueError|ImportError|KeyError' {log_file} > /dev/null 2>&1; then
                    echo "SCRIPT_ERROR:detected"
                    echo "SCRIPT_ERROR_DETAILS:"
                    grep -E 'Error:|Traceback|SyntaxError|NameError|TypeError|ValueError|ImportError|KeyError' {log_file} | tail -5
                fi
            fi &&
            
            # Get log tail for status parsing
            if test -f {log_file}; then
                echo "LOG_TAIL:"
                tail -100 {log_file}
            fi &&
            
            # Check if logs.tgz exists
            if test -f {logs_tgz}; then
                echo "LOGS_TGZ:exists"
            fi &&
            
            # Check status file
            if test -f {status_file} && test -s {status_file}; then
                echo "STATUS_FILE:"
                cat {status_file}
            else
                echo "STATUS_FILE:missing_or_empty"
            fi &&
            
            echo "=== STATUS_CHECK_END ==="
            """
            
            # Execute the compound command using centralized SSH builder
            ssh_cmd = self.node_manager.build_ssh_command(node['ip'], compound_cmd)
            process = subprocess.Popen(ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30)
            
            if process.returncode != 0:
                logger.error(f"Status check command failed for {node['name']}: {stderr.decode('utf-8')}")
                return {"status": "unknown", "current_operation": "Status check failed", "progress": 0}
            
            # Parse the compound output
            output = stdout.decode('utf-8')
            
            # Check for completion first (highest priority)
            if "STATUS:complete" in output or "RESULTS_FILE:exists" in output:
                logger.info(f"Node {node['name']} marked as complete by status check")
                return {"status": "complete", "current_operation": "Validation complete", "progress": 100}
            
            # Check for fatal tar extraction errors
            if "TAR_ERROR:detected" in output:
                error_details = ""
                if "TAR_ERROR_DETAILS:" in output:
                    error_details = output.split("TAR_ERROR_DETAILS:")[1].split("\n")[1:4]  # Get next 3 lines
                    error_details = "\n".join(error_details)
                
                logger.error(f"Fatal tar extraction error detected on {node['name']}: {error_details}")
                return {
                    "status": "error",
                    "current_operation": "Tech support extraction failed with fatal error",
                    "progress": 0,
                    "error": True,
                    "error_details": error_details
                }
            
            # Check for script errors
            if "SCRIPT_ERROR:detected" in output:
                error_details = ""
                if "SCRIPT_ERROR_DETAILS:" in output:
                    error_details = output.split("SCRIPT_ERROR_DETAILS:")[1].split("LOG_TAIL:")[0].strip()
                
                logger.error(f"Worker script error detected on node {node['name']}: {error_details}")
                
                # Check specifically for SyntaxError which indicates a broken script
                if "SyntaxError" in error_details:
                    return {
                        "status": "error", 
                        "current_operation": "Script execution failed due to syntax error",
                        "progress": 0,
                        "error": True,
                        "error_details": error_details
                    }
                
                # Other errors may or may not be fatal, but we should track them
                return {
                    "status": "error",
                    "current_operation": "Script execution encountered an error",
                    "progress": 0,
                    "error": True,
                    "error_details": error_details
                }
            
            # Parse log content for status
            log_content = ""
            if "LOG_TAIL:" in output:
                log_content = output.split("LOG_TAIL:")[1].split("LOGS_TGZ:")[0] if "LOGS_TGZ:" in output else output.split("LOG_TAIL:")[1].split("STATUS_FILE:")[0]
                log_content = log_content.strip()
            
            # Check tech support extraction status
            if "LOGS_TGZ:exists" in output or "Tech support extraction complete" in log_content:
                logger.info(f"Extraction complete for {node['name']} based on status check")
                return {"status": "running", "current_operation": "Tech support extraction complete", "progress": 80}
            
            # Check validation phase progress
            if "Running Validation Checks" in log_content:
                # Check for specific validation steps with granular progress reporting
                if "Checking system health" in log_content:
                    return {"status": "running", "current_operation": "Checking system health", "progress": 97}
                elif "Checking pod status" in log_content:
                    return {"status": "running", "current_operation": "Verifying pod status", "progress": 94}
                elif "Checking disk space" in log_content:
                    return {"status": "running", "current_operation": "Checking disk space usage", "progress": 90}
                elif "Checking node status" in log_content:
                    return {"status": "running", "current_operation": "Checking node status", "progress": 85}
                
                return {"status": "running", "current_operation": "Running validation checks", "progress": 82}
            
            # Check other progress indicators
            if "Starting validation" in log_content:
                return {"status": "running", "current_operation": "Starting validation", "progress": 20}
            elif "Selected tech support" in log_content:
                return {"status": "running", "current_operation": "Selected tech support", "progress": 50}
            elif "Extracting tech support" in log_content:
                return {"status": "running", "current_operation": "Extracting tech support", "progress": 60}
            elif "Running on node" in log_content:
                return {"status": "running", "current_operation": "Initializing worker script", "progress": 15}
            
            # Parse status file if available
            if "STATUS_FILE:" in output and "STATUS_FILE:missing_or_empty" not in output:
                status_content = output.split("STATUS_FILE:")[1].split("=== STATUS_CHECK_END ===")[0].strip()
                
                try:
                    status_data = json.loads(status_content)
                    logger.debug(f"Parsed status for {node['name']}: {status_data}")
                    
                    # If status says complete, return completion
                    if status_data.get("status") == "complete":
                        return {"status": "complete", "current_operation": status_data.get("current_operation", "Complete"), "progress": 100}
                        
                    return status_data
                except json.JSONDecodeError as e:
                    logger.debug(f"Invalid JSON in status from node {node['name']}: {str(e)}")
                    
                    # Look for "complete" in the output as a fallback
                    if "complete" in status_content.lower():
                        logger.info(f"Found 'complete' in status output for {node['name']}, marking as complete")
                        return {"status": "complete", "current_operation": "Complete (detected from output)", "progress": 100}
            
            # If status file is missing or empty, return initializing
            if "STATUS_FILE:missing_or_empty" in output:
                logger.warning(f"Status file not found or empty on node {node['name']}")
                return {"status": "initializing", "current_operation": "Deploying worker script", "progress": 10}
            
            # Default case
            return {"status": "initializing", "current_operation": "Starting worker script", "progress": 5}
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Status check timed out for node {node['name']}")
            return {"status": "unknown", "current_operation": "Status check timeout", "progress": 0}
        except Exception as e:
            logger.exception(f"Error checking status on node {node['name']}: {str(e)}")
            return {"status": "unknown", "current_operation": f"Error: {str(e)}", "progress": 0}
        
        # Default to early stage if we couldn't determine status
        return {"status": "initializing", "current_operation": "Deploying worker script", "progress": 5}
    
    def collect_results(self, node):
        """Collect results from a node with retry mechanism and proper timestamp handling"""
        logger.info(f"Collecting results from node {node['name']}")
        
        try:
            # Define expected results file path
            results_file = f"{self.base_dir}/{node['name']}_results.json"
            status_file = f"{self.base_dir}/{node['name']}_status.json"
            
            # First, try to get the completion timestamp from the status file
            with SSHCommand(self.node_manager, node, f"test -f {status_file} && cat {status_file} || echo 'no status file'") as ssh:
                status_output, _, _ = ssh.get_results(timeout=10)
            
            completion_time = None
            if "no status file" not in status_output:
                try:
                    status_data = json.loads(status_output)
                    if status_data.get("status") == "complete":
                        last_updated = status_data.get("last_updated")
                        if last_updated:
                            completion_time = datetime.strptime(last_updated, "%Y-%m-%d %H:%M:%S")
                            logger.info(f"Found completion timestamp for {node['name']}: {completion_time}")
                except json.JSONDecodeError:
                    logger.warning(f"Could not parse status file JSON for {node['name']}")
                except Exception as e:
                    logger.warning(f"Error processing completion time: {str(e)}")
            
            # Retry mechanism to check for results file
            retry_attempts = 3
            for attempt in range(retry_attempts):
                with SSHCommand(self.node_manager, node, f"test -f {results_file} && echo 'exists' || echo 'not found'") as ssh:
                    output, _, _ = ssh.get_results(timeout=5)
                
                if "exists" in output:
                    logger.info(f"Found results file on attempt {attempt+1} for {node['name']}")
                    break
                    
                # If not found and not last attempt, check status and wait
                if attempt < retry_attempts - 1:
                    with SSHCommand(self.node_manager, node, f"test -f {status_file} && cat {status_file} || echo 'no status file'") as ssh:
                        status_output, _, _ = ssh.get_results(timeout=5)
                    
                    logger.info(f"Status file for {node['name']} (attempt {attempt+1}): {status_output}")
                    
                    # If status says "complete", wait for results file
                    if "complete" in status_output.lower():
                        logger.info(f"Status indicates completion for {node['name']}, waiting for results file...")
                        time.sleep(3)
                    else:
                        # Not complete yet, wait a bit longer
                        logger.info(f"Node {node['name']} still processing, waiting...")
                        time.sleep(5)
            
            # Final check - if we still don't have the file, fail
            if "not found" in output:
                logger.error(f"Results file not found after {retry_attempts} attempts on node {node['name']}")
                return None
            
            # Use MultipleFileManager to handle all file resources
            with MultipleFileManager() as file_manager:
                # Create temp file for storing the results
                temp_path = tempfile.mktemp()
                temp_file = file_manager.open(temp_path, 'w+')
                
                # Get the results file content from the node
                with SSHCommand(self.node_manager, node, f"cat {results_file}") as ssh:
                    output, _, _ = ssh.get_results(timeout=10)
                
                if not output:
                    logger.error(f"Empty results file from node {node['name']}")
                    return None
                    
                # Write to temp file
                temp_file.write(output)
                temp_file.flush()
                temp_file.close()  # Close for reading
                
                # Re-open for reading
                temp_file = file_manager.open(temp_path, 'r')
                
                try:
                    # Parse the JSON results
                    results = json.loads(temp_file.read())
                    
                    # Add completion time to results if available
                    if completion_time:
                        results["completion_time"] = completion_time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Create local directory for results if needed
                    os.makedirs(self.results_dir, exist_ok=True)
                    
                    # Save the results locally
                    local_results_file = f"{self.results_dir}/{node['name']}_results.json"
                    results_file = file_manager.open(local_results_file, 'w')
                    json.dump(results, results_file, indent=2)
                    
                    logger.info(f"Results collected from node {node['name']}")
                    return results
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in results from node {node['name']}: {str(e)}")
                    
                    # Try to sanitize the output if it contains terminal escape sequences
                    sanitized_output = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', temp_file.read())
                    
                    try:
                        results = json.loads(sanitized_output)
                        logger.info(f"Successfully parsed sanitized JSON for {node['name']}")
                        
                        # Add completion time to results if available
                        if completion_time:
                            results["completion_time"] = completion_time.strftime("%Y-%m-%d %H:%M:%S")
                        
                        # Create local directory for results if needed
                        os.makedirs(self.results_dir, exist_ok=True)
                        
                        # Save the results locally
                        local_results_file = f"{self.results_dir}/{node['name']}_results.json"
                        results_file = file_manager.open(local_results_file, 'w')
                        json.dump(results, results_file, indent=2)
                        
                        return results
                    except json.JSONDecodeError:
                        logger.error(f"Still failed to parse sanitized JSON for {node['name']}")
                        return None
                        
        except Exception as e:
            logger.exception(f"Error collecting results from node {node['name']}: {str(e)}")
            return None

    def collect_node_output_log(self, node, stagger_delay=0):
        """Collect the output log from a node and save it to the results directory with retry logic"""
        import subprocess
        import shlex
        import time
        
        # Add stagger delay to spread out parallel SSH connections
        if stagger_delay > 0:
            time.sleep(stagger_delay)
            
        logger.info(f"Collecting output log from node {node['name']}")
        
        try:
            # Helper function to execute SSH command with retry logic
            def execute_ssh_with_retry(cmd, description, retries=3, delay=2):
                for attempt in range(retries):
                    if attempt > 0:
                        logger.debug(f"Retry {attempt}/{retries-1} for: {description}")
                        time.sleep(delay * attempt)  # Increasing delay
                    
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0:
                        return True, stdout.decode('utf-8'), stderr.decode('utf-8')
                    elif "Connection refused" in stderr.decode('utf-8'):
                        logger.debug(f"Connection refused on attempt {attempt + 1}, retrying...")
                        continue
                    else:
                        # Non-connection error, don't retry
                        return False, stdout.decode('utf-8'), stderr.decode('utf-8')
                
                return False, stdout.decode('utf-8'), stderr.decode('utf-8')
            
            # Define the log file path on the node
            log_file = f"{self.base_dir}/{node['name']}_output.log"
            
            # Make sure the results directory exists
            os.makedirs(self.results_dir, exist_ok=True)
            
            # Define the local path where we'll save the log
            local_log_file = f"{self.results_dir}/{node['name']}_output.log"
            
            # Get the log file content with retry logic
            cmd = self.node_manager.build_ssh_command(node['ip'], f"cat {log_file}")
            success, log_content, stderr = execute_ssh_with_retry(cmd, "collect output log")
            
            if success:
                # Save the log locally
                with open(local_log_file, 'w') as f:
                    f.write(log_content)
                
                logger.info(f"Output log collected from node {node['name']}")
                return True
            else:
                logger.error(f"Failed to collect output log from node {node['name']}: {stderr}")
                return False
            
        except Exception as e:
            logger.exception(f"Error collecting output log from node {node['name']}: {str(e)}")
            return False

    def cleanup_node_directory(self, node, stagger_delay=0):
        """Clean up the worker script directory on a node with retry logic and staggered start"""
        import time
        
        # Add stagger delay to spread out parallel SSH connections
        if stagger_delay > 0:
            time.sleep(stagger_delay)
            
        logger.info(f"Cleaning up temporary files on node {node['name']}")
        
        try:
            
            # Helper function to execute SSH command with retry logic
            def execute_ssh_with_retry(cmd, description, retries=3, delay=2):
                for attempt in range(retries):
                    if attempt > 0:
                        logger.debug(f"Retry {attempt}/{retries-1} for: {description}")
                        time.sleep(delay * attempt)  # Increasing delay
                    
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate(timeout=30)
                    
                    if process.returncode == 0:
                        return True, stdout.decode('utf-8'), stderr.decode('utf-8')
                    elif "Connection refused" in stderr.decode('utf-8'):
                        logger.debug(f"Connection refused on attempt {attempt + 1}, retrying cleanup...")
                        continue
                    else:
                        # Non-connection error, don't retry
                        return False, stdout.decode('utf-8'), stderr.decode('utf-8')
                
                return False, stdout.decode('utf-8'), stderr.decode('utf-8')
            
            cmd = self.node_manager.build_ssh_command(node['ip'], f"rm -rf {self.base_dir}")
            success, stdout, stderr = execute_ssh_with_retry(cmd, "cleanup temporary files")
            
            if success:
                logger.info(f"Successfully cleaned up temporary files on node {node['name']}")
                return True
            else:
                logger.error(f"Failed to clean up temporary files on node {node['name']}: {stderr}")
                return False
        except Exception as e:
            logger.exception(f"Error cleaning up temporary files on node {node['name']}: {str(e)}")
            return False

def get_worker_script_content():
    """
    Returns the worker script content by reading from the worker_functions.py file.
    This approach allows developing the worker script as a normal Python file.
    If worker_functions.py isn't found, looks for other candidate Python files.
    """
    try:
        # Get the path of the worker script relative to this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_script_path = os.path.join(script_dir, "worker_functions.py")
        
        # Check if the primary file exists
        if not os.path.exists(worker_script_path):
            logger.warning(f"Primary worker script not found at {worker_script_path}, looking for alternatives")
            
            # Look for other Python files in the directory
            candidate_files = [f for f in os.listdir(script_dir) if f.endswith('.py') and f != os.path.basename(__file__)]
            logger.debug(f"Found {len(candidate_files)} candidate Python files: {candidate_files}")
            
            # Check each file for "Worker script" in the first 10 lines
            for file in candidate_files:
                file_path = os.path.join(script_dir, file)
                try:
                    with open(file_path, "r") as f:
                        # Read the first 10 lines
                        first_lines = "".join([f.readline() for _ in range(10)])
                        if "Worker script" in first_lines:
                            logger.info(f"Found alternative worker script in {file}")
                            worker_script_path = file_path
                            break
                except Exception as e:
                    logger.warning(f"Error reading file {file}: {str(e)}")
            
            if worker_script_path == os.path.join(script_dir, "worker_functions.py"):
                logger.error(f"Could not find any suitable worker script files")
                raise FileNotFoundError(f"Worker script not found at {worker_script_path} and no alternatives found")
        
        # Read the worker script file
        with open(worker_script_path, "r") as f:
            worker_script = f.read()
        
        logger.info(f"Successfully loaded worker script from {worker_script_path}")
        return worker_script
        
    except Exception as e:
        logger.exception(f"Error loading worker script: {str(e)}")
        raise RuntimeError(f"Failed to load worker script: {str(e)}")

def display_check_results(nodes_to_monitor, script_manager):
    """Display check results with parallel monitoring for better performance"""
    # Track node status and results
    nodes_status = {}
    nodes_results = {}
    nodes_error = {}
    
    # Set up console formatting
    PASS = "\033[1;32mPASS\033[0m"
    FAIL = "\033[1;31mFAIL\033[0m"
    WARNING = "\033[1;33mWARNING\033[0m"
    
    # Track start time
    overall_start_time = time.time()
    nodes_start_time = {node["name"]: time.time() for node in nodes_to_monitor}
    
    logger.info(f"Monitoring validation progress for {len(nodes_to_monitor)} nodes")
    print(f"\nRunning validation checks on {len(nodes_to_monitor)} Nexus Dashboard nodes...")
    
    # Maximum monitoring time (30 minutes)
    max_monitoring_time = 1800
    monitoring_interval = 2
    
    all_complete = False
    start_time = time.time()
    
    # Determine optimal concurrency for monitoring
    max_monitor_threads = min(len(nodes_to_monitor), 10)  # Cap at 10 threads
    
    while not all_complete and (time.time() - start_time) < max_monitoring_time:
        all_complete = True
        current_checks = {}
        
        # Check status for all nodes in parallel
        incomplete_nodes = [node for node in nodes_to_monitor 
                          if nodes_status.get(node["name"]) != "complete" 
                          and nodes_status.get(node["name"]) != "error"]
        
        if not incomplete_nodes:
            break  # All nodes are complete or have errors
        
        # Define function to check a single node's status
        def check_node_status(node):
            node_name = node["name"]
            status = script_manager.check_worker_status(node)
            return node_name, status
        
        # Execute status checks in parallel
        statuses = {}
        with ThreadPoolExecutor(max_workers=max_monitor_threads) as executor:
            futures = [executor.submit(check_node_status, node) for node in incomplete_nodes]
            for future in as_completed(futures):
                try:
                    node_name, status = future.result()
                    statuses[node_name] = status
                except Exception as e:
                    logger.error(f"Error checking node status: {str(e)}")
        
        # Process collected status information
        for node in nodes_to_monitor:
            node_name = node["name"]
            
            # Skip already completed nodes
            if nodes_status.get(node_name) == "complete" or nodes_status.get(node_name) == "error":
                continue
                
            # Get status info from our parallel collection
            if node_name not in statuses:
                continue
                
            status = statuses[node_name]
            
            # Check for error condition
            if status.get("error", False):
                logger.error(f"Node {node_name} worker script failed with error")
                nodes_error[node_name] = True
                nodes_status[node_name] = "error"
                
                # Display error details
                error_details = status.get("error_details", "No details available")
                print(f"\n{FAIL} Worker script error on node {node_name}:")
                print("-" * 80)
                print(error_details)
                print("-" * 80)
                continue
                
            # Node is still running
            if status["status"] != "complete":
                all_complete = False
                
                # Update status info
                nodes_status[node_name] = status["status"]
                current_operation = status.get("current_operation", "Processing...")
                
                # Only log new operations to avoid spam
                if node_name not in current_checks or current_checks[node_name] != current_operation:
                    current_checks[node_name] = current_operation
                    
                    # Format with consistent spacing
                    print(f"[Node {node_name}] {current_operation}")
            else:
                # Node is complete - collect results
                if nodes_status.get(node_name) != "complete":
                    nodes_status[node_name] = "complete"
                    print(f"[Node {node_name}] Validation complete")
                    
                    # Results will be collected later in parallel
        
        # Sleep before next check if not complete
        if not all_complete:
            time.sleep(monitoring_interval)
    
    # Handle timeout
    if not all_complete:
        print(f"\n{WARNING} Monitoring timed out after {max_monitoring_time/60:.1f} minutes")
    
    # Collect results and output logs from completed nodes in parallel
    completed_nodes = [node for node in nodes_to_monitor 
                      if nodes_status.get(node["name"]) == "complete"]
    
    # Don't need to collect results if no nodes completed
    if completed_nodes:
        print("Collecting results and logs from all nodes...")
        
        # Define function to collect a single node's results and logs with staggered start
        def collect_node_results_and_logs(node, stagger_delay=0):
            node_name = node["name"]
            
            # Add stagger delay to spread out parallel SSH connections
            if stagger_delay > 0:
                time.sleep(stagger_delay)
            
            # Collect results
            results = script_manager.collect_results(node)
            
            # Also collect the output log with stagger delay
            script_manager.collect_node_output_log(node, stagger_delay=0.5)  # Small additional delay
            
            return node_name, results
        
        # Execute result and log collection in parallel with staggered starts
        with ThreadPoolExecutor(max_workers=max_monitor_threads) as executor:
            # Submit tasks with staggered delays to spread out SSH connections
            future_to_node = {}
            for i, node in enumerate(completed_nodes):
                stagger_delay = i * 1.5  # 1.5-second stagger between parallel starts
                future_to_node[executor.submit(collect_node_results_and_logs, node, stagger_delay)] = node
                
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    node_name, results = future.result()
                    if results:
                        nodes_results[node_name] = results
                except Exception as e:
                    logger.error(f"Error collecting results from {node['name']}: {str(e)}")
    
    # Calculate monitoring time
    total_time = time.time() - overall_start_time
    
    # Display completion message
    print(f"\nMonitoring completed in {int(total_time//60)} minutes {int(total_time%60)} seconds\n")
    
    # Return collected results
    return nodes_results

class MultipleFileManager:
    """Context manager for handling multiple file resources"""
    
    def __init__(self):
        self.files = []
        self.paths = []
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close all files when exiting context"""
        for f in self.files:
            try:
                if not f.closed:
                    f.close()
            except:
                pass
        
        return False  # Don't suppress exceptions
        
    def open(self, path, mode='r'):
        """Open a file and track it for cleanup"""
        f = open(path, mode)
        self.files.append(f)
        self.paths.append(path)
        return f
        
    def get_file(self, index):
        """Get file by index"""
        if 0 <= index < len(self.files):
            return self.files[index]
        return None
    
def process_all_nodes(node_manager, tech_choice, debug_mode=False, skipped_nodes_info=None):
    """Process all nodes with validation script using optimal resource-based concurrency"""
    # Record process start time
    process_start_time = time.time()
    
    # Check system resources to determine optimal concurrency
    resources = check_system_resources()
    max_concurrent_nodes = resources.get("recommended_parallelism", 2)
    logger.info(f"Using maximum concurrency of {max_concurrent_nodes} nodes")
    
    nodes = node_manager.nodes
    tech_manager = TechSupportManager(node_manager)
    script_manager = WorkerScriptManager(node_manager)
    
    # Initialize skipped_nodes_info if not provided
    if skipped_nodes_info is None:
        skipped_nodes_info = {'disk_space_issues': [], 'large_log_files': []}
    
    # Initialize result collections
    all_results = {}
    overall_status = "PASS"
    node_operations = {}
    successful_nodes = []
    # Store debug flag and base_dir for use at the end of script
    debug_data = {
        "enabled": debug_mode,
        "base_dir": script_manager.base_dir,
        "successful_nodes": []
    }
    
    # First, handle tech supports for all nodes based on user choice
    print_section("Tech Support Selection/Generation")
    tech_support_paths = {}
    
    if tech_choice == "1":
        # Generate new tech supports IN PARALLEL for all nodes
        print("Generating tech supports for all nodes in parallel.")
        
        # Use ThreadPoolExecutor to generate tech supports in parallel
        try:
            with ThreadPoolExecutor(max_workers=max_concurrent_nodes) as executor:
                # Create a future for each node
                future_to_node = {executor.submit(tech_manager.generate_techsupport, node): node for node in nodes}
                
                # Process results as they complete
                for future in as_completed(future_to_node):
                    node = future_to_node[future]
                    node_name = node["name"]
                    try:
                        tech_support_path = future.result()
                        if not tech_support_path:
                            print(f"{FAIL} Failed to generate tech support on {node_name}")
                            continue
                        tech_support_paths[node_name] = tech_support_path
                        print(f"Generated tech support on {node_name}: {os.path.basename(tech_support_path)}")
                    except Exception as exc:
                        logger.exception(f"Error generating tech support for {node_name}: {exc}")
                        print(f"{FAIL} Error generating tech support for {node_name}: {str(exc)}")
        except KeyboardInterrupt:
            print("\n\n🛑 Tech support generation interrupted by user. Shutting down...")
            logger.warning("Tech support generation interrupted by user (Ctrl+C)")
            sys.exit(0)
    else:
        # Fetch tech support listings for all nodes in parallel first
        print("Checking for tech support files on all nodes...")
        node_tech_support_files = {}
        
        with ThreadPoolExecutor(max_workers=max_concurrent_nodes) as executor:
            # Start a thread for each node to fetch available tech support files
            future_to_node = {executor.submit(tech_manager.list_techsupport_files, node): node for node in nodes}
            
            # Process results as they complete
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    tech_files = future.result()
                    if tech_files:
                        node_tech_support_files[node["name"]] = tech_files
                except Exception as exc:
                    logger.exception(f"Error listing tech support files for {node['name']}: {exc}")
                    print(f"{FAIL} Error listing tech support files for {node['name']}: {str(exc)}")
        
        # Now ask user to select tech support for each node sequentially
        # (We must do this sequentially as it's interactive)
        for node in nodes:
            node_name = node["name"]
            if node_name not in node_tech_support_files:
                print(f"{FAIL} No tech support files found for {node_name}")
                continue
                
            tech_files = node_tech_support_files[node_name]
            print(f"\nTech support files available on {node_name} ({node['ip']}):")
            print()
            for idx, file_info in enumerate(tech_files, 1):
                print(f"{idx}. {file_info['name']}")
                print(f"   Size: {file_info['size']}, Created: {file_info['date']}")
                print("   ")
            
            # Ask user to select a file
            while True:
                try:
                    range_str = str(len(tech_files)) if len(tech_files) == 1 else f"1-{len(tech_files)}"
                    choice = input(f"\nSelect tech support file for {node_name} ({range_str}, or 0 to skip): ")
                    if choice == '0':
                        print(f"Skipping node {node_name}.")
                        break
                        
                    idx = int(choice) - 1
                    if 0 <= idx < len(tech_files):
                        selected_file = tech_files[idx]["path"]
                        print(f"Selected: {tech_files[idx]['name']}")
                        tech_support_paths[node_name] = selected_file
                        break
                    else:
                        print(f"Please enter a number between 0 and {len(tech_files)}")
                except ValueError:
                    print("Please enter a valid number")
            
            if node_name not in tech_support_paths and not tech_files:
                print(f"\nNo tech support files found on {node_name}.")
                print(f"Would you like to generate a new tech support? (y/n)")
                choice = input("> ")
                
                if choice.lower() == 'y':
                    print(f"Generating tech support on {node_name}...")
                    tech_support_path = tech_manager.generate_techsupport(node)
                    if tech_support_path:
                        tech_support_paths[node_name] = tech_support_path
                        print(f"Generated tech support on {node_name}: {os.path.basename(tech_support_path)}")
    
    # Check if we have any tech supports to process
    if not tech_support_paths:
        print(f"{FAIL} No tech supports were selected or generated. Exiting.")
        return {}
    
    # PRE-FLIGHT CHECK: Verify /tmp space on all nodes before proceeding
    print_section("Pre-Flight /tmp Space Validation")
    print("Checking /tmp disk space on all nodes before extraction...")
    print("This validation ensures sufficient space for tech support extraction (70% threshold).\n")
    
    space_check_failed = False
    space_check_results = {}
    
    # Check space on all nodes that have tech supports
    for node in nodes:
        node_name = node["name"]
        if node_name not in tech_support_paths:
            continue
        
        tech_support_path = tech_support_paths[node_name]
        print(f"Checking space on {node_name}...", end=" ")
        
        has_space, current_usage, projected_usage, ts_size_gb, error_msg = node_manager.check_tmp_space(node, tech_support_path)
        space_check_results[node_name] = {
            "has_space": has_space,
            "current_usage": current_usage,
            "projected_usage": projected_usage,
            "ts_size_gb": ts_size_gb,
            "error_msg": error_msg
        }
        
        if has_space:
            print(f"{PASS}")
            print(f"  Tech support: {ts_size_gb:.2f} GB | Current: {current_usage:.1f}% | Projected: {projected_usage:.1f}%")
            # Warn if tech support is abnormally large
            if ts_size_gb > 10:
                print(f"  {WARNING} Tech support file is unusually large ({ts_size_gb:.2f} GB)")
                print(f"      This may indicate excessive logs or other issues")
        else:
            print(f"{FAIL}")
            print(f"  {error_msg}")
            if ts_size_gb > 0:
                print(f"  Tech support size: {ts_size_gb:.2f} GB")
            space_check_failed = True
    
    # If any node failed the space check, abort the entire operation
    if space_check_failed:
        print(f"\n{FAIL} Pre-flight space check FAILED on one or more nodes!")
        print("\nThe following nodes do not have sufficient /tmp space:")
        for node_name, result in space_check_results.items():
            if not result["has_space"]:
                print(f"  • {node_name}: {result['error_msg']}")
        
        print(f"\n{WARNING} ABORTING validation to prevent 'No space left on device' errors.")
        print("\nRecommended actions:")
        print("  1. Free up space on /tmp filesystem(s)")
        print("  2. Remove old tech support files or extracted directories")
        print("  3. Check for large temporary files that can be deleted")
        print("  4. Re-run this script after space has been freed")
        print(f"\nExiting without making any changes.")
        return {}
    
    print(f"\n{PASS} All nodes passed /tmp space validation!")
    print("Proceeding with worker script deployment...\n")
    
    # Get the worker script content once
    worker_script_content = get_worker_script_content()
    
    # Deploy worker scripts and process tech supports
    print_section("Deploying Worker Scripts and Starting Validation")
    
    # Deploy scripts to all nodes
    nodes_to_process = [node for node in nodes if node["name"] in tech_support_paths]
    if not nodes_to_process:
        print(f"{FAIL} No nodes found with tech supports to process.")
        return {}
    
    # Process nodes in batches based on resource capacity
    nodes_batches = []
    for i in range(0, len(nodes_to_process), max_concurrent_nodes):
        batch = nodes_to_process[i:i + max_concurrent_nodes]
        nodes_batches.append(batch)
    
    logger.info(f"Processing {len(nodes_to_process)} nodes in {len(nodes_batches)} batches")
    
    # Helper function to deploy and execute for one node
    def deploy_and_execute_node(node, stagger_delay=0):
        node_name = node["name"]
        tech_support_path = tech_support_paths[node_name]
        
        print(f"Deploying worker script to node {node_name}...")
        logger.info(f"Deploying worker script to node {node_name}")
        script_path = script_manager.deploy_worker_script(node, worker_script_content, stagger_delay)
        if not script_path:
            print(f"{FAIL} Failed to deploy worker script to {node_name}")
            return None
            
        print(f"{PASS} Worker script deployed to {node_name}")
        logger.info(f"Worker script deployed to node {node_name}")
        
        operation = "generate" if tech_choice == "1" else "select"
        
        print(f"Starting validation on node {node_name}...")
        logger.info(f"Executing worker script on node {node_name}")
        if script_manager.execute_worker_script(node, script_path, tech_support_path, operation, stagger_delay):
            print(f"{PASS} Validation started on {node_name}")
            logger.info(f"Worker script executed on node {node_name}")
            return {
                "node": node,
                "script_path": script_path,
                "tech_support_path": tech_support_path
            }
        else:
            print(f"{FAIL} Failed to execute worker script on {node_name}")
            logger.error(f"Failed to execute worker script on node {node_name}")
            return None
    
    # Process each batch of nodes
    for batch_num, batch in enumerate(nodes_batches, 1):
        logger.info(f"Processing batch {batch_num}/{len(nodes_batches)} with {len(batch)} nodes")
        
        # Use ThreadPoolExecutor to process each batch in parallel with staggered starts
        batch_results = []
        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            # Submit tasks with staggered delays to spread out SSH connections
            future_to_node = {}
            for i, node in enumerate(batch):
                stagger_delay = i * 1.5  # 1.5-second stagger between parallel starts
                future_to_node[executor.submit(deploy_and_execute_node, node, stagger_delay)] = node
                
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    result = future.result()
                    if result:
                        node_operations[node["name"]] = result
                        successful_nodes.append(node["name"])
                        debug_data["successful_nodes"].append(node["name"])
                        batch_results.append(node)
                except Exception as exc:
                    logger.exception(f"Node {node['name']} generated an exception: {exc}")
                    print(f"{FAIL} Error processing node {node['name']}: {str(exc)}")
                    
        # If no nodes in this batch started successfully, continue to next batch
        if not batch_results:
            logger.warning(f"No nodes in batch {batch_num} were successfully started")
            continue
            
        # Monitor validation progress for current batch
        print(f"\nMonitoring validation progress on {len(batch_results)} nodes in batch {batch_num}...")
        
        # Use the updated display check results function to show progress
        batch_node_results = display_check_results(batch_results, script_manager)
        
        # Collect results from this batch
        if batch_node_results:
            all_results.update(batch_node_results)
            
            # Update overall status based on this batch's results
            for node_name, results in batch_node_results.items():
                for check_name, check_result in results["checks"].items():
                    if check_result["status"] == "FAIL":
                        overall_status = "FAIL"
                    elif check_result["status"] == "WARNING" and overall_status != "FAIL":
                        overall_status = "WARNING"
    
    # After results collection, cleanup unless debug mode is enabled
    if not debug_mode and successful_nodes:
        print_section("Cleaning Up Temporary Files")
        print(f"Cleaning up temporary files from {len(successful_nodes)} nodes...")
        
        cleanup_results = []
        with ThreadPoolExecutor(max_workers=max_concurrent_nodes) as executor:
            # Only clean up nodes that were successfully processed
            nodes_to_cleanup = [node for node in nodes if node["name"] in successful_nodes]
            
            # Submit cleanup tasks with staggered delays to spread out SSH connections
            future_to_node = {}
            for i, node in enumerate(nodes_to_cleanup):
                stagger_delay = i * 1.5  # 1.5-second stagger between parallel starts
                future_to_node[executor.submit(script_manager.cleanup_node_directory, node, stagger_delay)] = node
            
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    success = future.result()
                    if success:
                        print(f"{PASS} Cleaned up temporary files on {node['name']}")
                    else:
                        print(f"{WARNING} Failed to clean up temporary files on {node['name']}")
                except Exception as exc:
                    logger.exception(f"Error cleaning up node {node['name']}: {exc}")
                    print(f"{WARNING} Error cleaning up temporary files on {node['name']}: {str(exc)}")
    
    # Calculate timing info
    total_time = time.time() - process_start_time
    timing_info = {
        "total_time": total_time,
        "node_times": {}
    }
    
    # Generate the final report
    if all_results:
        generate_report(all_results, None, overall_status, timing_info, skipped_nodes_info)
    else:
        print(f"{FAIL} No results were collected from any nodes.")
    
    # Display debug mode warning AFTER the report if debug mode was enabled
    if debug_mode and successful_nodes:
        warning_message = f"\n{WARNING} Debug mode enabled: Temporary files were NOT removed from nodes."
        warning_message += f"\nTemporary files remain in {script_manager.base_dir} on each node for debugging purposes."
        print(warning_message)
    
    # Store debug information in results for main function to use later
    if debug_mode:
        all_results["_debug_info"] = debug_data
    
    return all_results

def print_section(title):
    """Print a section title with formatting"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")

def generate_report(all_results, version, overall_status, timing_info=None, skipped_nodes_info=None):
    """Generate a final report based on aggregated results with clear check-by-check output"""
    print_section("Pre-upgrade Validation Report")
    
    # Use MultipleFileManager to handle all file resources
    with MultipleFileManager() as file_manager:
        # Create output directory
        results_dir = os.path.join(os.getcwd(), "final-results")
        os.makedirs(results_dir, exist_ok=True)
        
        # Open the summary report file
        summary_file = file_manager.open(os.path.join(results_dir, "validation_summary.txt"), 'w')
        
        # Open the detailed report JSON file
        details_file = file_manager.open(os.path.join(results_dir, "validation_details.json"), 'w')
        
        # Write header to summary file
        summary_file.write("NEXUS DASHBOARD PRE-UPGRADE VALIDATION REPORT\n")
        summary_file.write("="*50 + "\n\n")
        
        # Display timing information if available
        if timing_info:
            total_time = timing_info.get("total_time", 0)
            total_minutes = int(total_time // 60)
            total_seconds = int(total_time % 60)
            timing_message = f"Total validation time: {total_minutes} min {total_seconds} sec\n"
            print(timing_message)
            summary_file.write(timing_message + "\n")
            
            # Calculate node times
            node_times = timing_info.get("node_times", {})
            if node_times:
                print("\nProcessing time per node:")
                summary_file.write("Processing time per node:\n")
                for node_name, node_time in node_times.items():
                    node_minutes = int(node_time // 60)
                    node_seconds = int(node_time % 60)
                    node_timing = f"  {node_name}: {node_minutes} min {node_seconds} sec\n"
                    print(node_timing, end="")
                    summary_file.write(node_timing)
                
                summary_file.write("\n")  # Add blank line
            
            print("")  # Add blank line
        
        if version:
            version_info = f"Nexus Dashboard Version: {version}\n"
            print(version_info, end="")
            summary_file.write(version_info)
            
        timestamp = f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        print(timestamp, end="")
        summary_file.write(timestamp)
        
        # Add skipped nodes section if there were any
        if skipped_nodes_info and skipped_nodes_info.get('disk_space_issues'):
            disk_space_issues = skipped_nodes_info['disk_space_issues']
            skipped_header = f"⚠️  NODES SKIPPED DUE TO DISK SPACE ISSUES\n"
            skipped_separator = "="*50 + "\n\n"
            
            print(skipped_header, end="")
            print(skipped_separator, end="")
            summary_file.write(skipped_header)
            summary_file.write(skipped_separator)
            
            for issue in disk_space_issues:
                node = issue['node']
                directories = issue['directories']
                
                node_info = f"Node: {node['name']} ({node['ip']})\n"
                print(node_info, end="")
                summary_file.write(node_info)
                
                if directories:
                    dirs_header = "Directories over 80% usage:\n"
                    print(dirs_header, end="")
                    summary_file.write(dirs_header)
                    
                    for mount_point, usage_pct in directories:
                        dir_info = f"  • {mount_point}: {usage_pct:.0f}% full\n"
                        print(dir_info, end="")
                        summary_file.write(dir_info)
                else:
                    error_info = f"  • {issue['error']}\n"
                    print(error_info, end="")
                    summary_file.write(error_info)
                
                recommendation = f"Recommendation: Contact TAC to help clear these directories before\n"
                recommendation += f"                rerunning the script against {node['name']}\n\n"
                print(recommendation, end="")
                summary_file.write(recommendation)
            
            print("")  # Add blank line
            summary_file.write("\n")
        
        # Add skipped nodes section for large log files if there were any
        if skipped_nodes_info and skipped_nodes_info.get('large_log_files'):
            large_log_issues = skipped_nodes_info['large_log_files']
            skipped_header = f"⚠️  NODES SKIPPED DUE TO LARGE EVENTMONITORING LOG FILES\n"
            skipped_separator = "="*50 + "\n\n"
            
            print(skipped_header, end="")
            print(skipped_separator, end="")
            summary_file.write(skipped_header)
            summary_file.write(skipped_separator)
            
            for issue in large_log_issues:
                node = issue['node']
                large_files = issue['large_files']
                
                node_info = f"Node: {node['name']} ({node['ip']})\n"
                print(node_info, end="")
                summary_file.write(node_info)
                
                if large_files:
                    files_header = "Large eventmonitoring log files (>= 1G):\n"
                    print(files_header, end="")
                    summary_file.write(files_header)
                    
                    for file_size in large_files:
                        file_info = f"  • {file_size}\n"
                        print(file_info, end="")
                        summary_file.write(file_info)
                else:
                    error_info = f"  • {issue['error']}\n"
                    print(error_info, end="")
                    summary_file.write(error_info)
                
                recommendation = f"Recommendation: Contact TAC to help resolve this issue before\n"
                recommendation += f"                collecting tech support on {node['name']}\n\n"
                print(recommendation, end="")
                summary_file.write(recommendation)
            
            print("")  # Add blank line
            summary_file.write("\n")
        
        # Define check order and display formatting
        PASS = "\033[1;32mPASS\033[0m"
        FAIL = "\033[1;31mFAIL\033[0m"
        WARNING = "\033[1;33mWARNING\033[0m"
        
        # For plain text report (no colors)
        PASS_TXT = "PASS"
        FAIL_TXT = "FAIL"
        WARNING_TXT = "WARNING"
        
        # Define the specific order of checks
        check_order = [
            "techsupport",
            "version_check",
            "node_status", 
            "ping_check",
            "subnet_check",
            "persistent_ip_check",
            "disk_space", 
            "pod_status", 
            "system_health",
            "nxos_discovery_service",
            "backup_failure_check",
            "nameserver_duplicate_check",
            "legacy_ndi_elasticsearch_check",
            "ntp_auth_check",
            "certificate_check",
            "iso_check",
            "lvm_pvs_check",
            "atom0_nvme_check",
            "atom0_vg_check",
            "vnd_app_large_check"
        ]
        
        # Organize by check type instead of by node
        all_checks = {}
        for node_name, node_results in all_results.items():
            for check_name, check_result in node_results["checks"].items():
                if check_name not in all_checks:
                    all_checks[check_name] = {
                        "status": "PASS",
                        "nodes": {},
                        "explanation": None,
                        "recommendation": None,
                        "reference": None
                    }
                
                # Update overall check status
                if check_result["status"] == "FAIL":
                    all_checks[check_name]["status"] = "FAIL"
                elif check_result["status"] == "WARNING" and all_checks[check_name]["status"] != "FAIL":
                    all_checks[check_name]["status"] = "WARNING"
                    
                # Store node's result for this check
                all_checks[check_name]["nodes"][node_name] = check_result
                
                # Extract explanation, recommendation, and reference if present in details
                if "details" in check_result and check_result["details"]:
                    for detail in check_result["details"]:
                        if detail.strip().startswith("\n  Explanation:"):
                            all_checks[check_name]["explanation"] = detail
                        elif detail.strip().startswith("\n  Recommendation:"):
                            all_checks[check_name]["recommendation"] = detail
                        elif detail.strip().startswith("\n  Reference:"):
                            all_checks[check_name]["reference"] = detail
                
                # ALSO check for explanation and recommendation at the top level
                # This handles our modified checks that store these at the top level
                # Only update explanation/recommendation if this node's status is FAIL, or if no explanation exists yet
                should_update_explanation = (
                    check_result["status"] == "FAIL" or 
                    all_checks[check_name]["explanation"] is None
                )
                
                if "explanation" in check_result and check_result["explanation"] and should_update_explanation:
                    explanation_text = f"\n  Explanation:\n  {check_result['explanation']}"
                    all_checks[check_name]["explanation"] = explanation_text
                    
                if "recommendation" in check_result and check_result["recommendation"] and should_update_explanation:
                    recommendation_text = f"\n  Recommendation:\n  {check_result['recommendation']}"
                    all_checks[check_name]["recommendation"] = recommendation_text
                    
                if "reference" in check_result and check_result["reference"] and should_update_explanation:
                    reference_text = f"\n  Reference:\n  {check_result['reference']}"
                    all_checks[check_name]["reference"] = reference_text
        
        # Order the checks according to our defined sequence
        ordered_checks = []
        
        # First add checks in our defined order
        for check in check_order:
            if check in all_checks:
                ordered_checks.append(check)
        
        # Then add any checks not in our predefined list (if any)
        for check in all_checks:
            if check not in ordered_checks:
                ordered_checks.append(check)
        
        # Write the detailed JSON data
        json.dump(all_checks, details_file)
        
        # Display each check result
        for i, check_name in enumerate(ordered_checks, 1):
            check_info = all_checks[check_name]
            check_status = check_info["status"]
            
            # Format check name for display
            display_name = check_name.replace("_", " ").title()
            
            # Determine the status indicator for console
            if check_status == "FAIL":
                status_indicator = f"{FAIL} - UPGRADE FAILURE!!"
                status_indicator_txt = f"{FAIL_TXT} - UPGRADE FAILURE!!"
            elif check_status == "WARNING":
                status_indicator = f"{WARNING} - ATTENTION REQUIRED"
                status_indicator_txt = f"{WARNING_TXT} - ATTENTION REQUIRED"
            else:
                status_indicator = PASS
                status_indicator_txt = PASS_TXT
            
            # Display check header with right-aligned status for console
            console_line = f"[Check {i:2d}/{len(ordered_checks):2d}] {display_name}..."
            right_padding = 80 - len(display_name) - 15
            console_line += f"{' ' * right_padding}{status_indicator}"
            print(console_line)
            
            # Write to summary file (without color codes)
            summary_line = f"[Check {i:2d}/{len(ordered_checks):2d}] {display_name}..."
            summary_line += f"{' ' * right_padding}{status_indicator_txt}\n"
            summary_file.write(summary_line)
            
            # Always show node details table, even for PASS status
            node_indent = "  "  # 2 spaces indent for Node column
            header_line = f"{node_indent}{'Node':<10} {'Status':<8} {'Details'}"
            separator_line = f"{node_indent}{'-'*10} {'-'*8} {'-'*50}"
            
            # Only print the header if there are any nodes with results to show
            if check_info["nodes"]:
                # Always show table headers
                print(header_line)
                print(separator_line)
                summary_file.write(header_line + "\n")
                summary_file.write(separator_line + "\n")
                
                # Track if any failures or warnings were detected for this check
                failures_detected = False
                
                # Print all nodes and their details
                for node_name, node_result in sorted(check_info["nodes"].items()):
                    status = node_result["status"]
                    
                    # Track if there are failures or warnings in this check
                    if status == "FAIL" or status == "WARNING":
                        failures_detected = True
                    
                    # Format status for console
                    if status == "FAIL":
                        status_str = FAIL
                        status_str_txt = FAIL_TXT
                    elif status == "WARNING":
                        status_str = WARNING
                        status_str_txt = WARNING_TXT
                    else:
                        status_str = PASS
                        status_str_txt = PASS_TXT
                    
                    # Filter out the explanation, recommendation, and reference from node details
                    filtered_details = []
                    for detail in node_result.get("details", []):
                        if not (detail.strip().startswith("\n  Explanation:") or 
                               detail.strip().startswith("\n  Recommendation:") or
                               detail.strip().startswith("\n  Reference:")):
                            filtered_details.append(detail)
                    
                    # For PASS status with no details, show empty string (no details)
                    if status == "PASS" and not filtered_details:
                        filtered_details = [""]
                    
                    # Display first detail line with properly aligned details
                    if filtered_details:
                        # Calculate padding needed for status column alignment
                        # Status column should be 8 chars wide (to fit "WARNING")
                        # ANSI codes don't count toward display width, so we need to pad based on actual text
                        if status == "FAIL":
                            status_padding = 4  # "FAIL" is 4 chars, need 4 more spaces to reach 8
                        elif status == "WARNING":
                            status_padding = 1  # "WARNING" is 7 chars, need 1 more space to reach 8
                        else:  # PASS
                            status_padding = 4  # "PASS" is 4 chars, need 4 more spaces to reach 8
                        
                        # First line includes node name and status with proper padding
                        detail_line = f"{node_indent}{node_name:<10} {status_str}{' ' * status_padding} {filtered_details[0]}"
                        print(detail_line)
                        
                        # For text file (proper alignment without ANSI color codes)
                        summary_file.write(f"{node_indent}{node_name:<10} {status_str_txt:<8} {filtered_details[0]}\n")
                        
                        # Display additional detail lines with fixed alignment indent
                        for detail in filtered_details[1:]:
                            # For console: indent properly to align with Details column (2 + 10 + 1 + 8 + 1 = 22)
                            print(f"{node_indent}{' '*10} {' '*8} {detail}")
                            # For text file: use consistent alignment
                            summary_file.write(f"{node_indent}{' '*10} {' '*8} {detail}\n")
                    else:
                        # Calculate padding for no details case
                        if status == "FAIL":
                            status_padding = 4
                        elif status == "WARNING":
                            status_padding = 1
                        else:  # PASS
                            status_padding = 4
                        
                        # For console
                        no_details = f"{node_indent}{node_name:<10} {status_str}{' ' * status_padding} No details available"
                        print(no_details)
                        # For text file
                        summary_file.write(f"{node_indent}{node_name:<10} {status_str_txt:<8} No details available\n")
                
                # AFTER displaying all nodes, print the explanation, recommendation, and reference once
                if failures_detected:
                    # Add explanations and recommendations after all nodes are printed
                    if check_info["explanation"]:
                        print(f"\n{check_info['explanation']}")
                        summary_file.write(f"\n{check_info['explanation']}\n")
                        
                    if check_info["recommendation"]:
                        print(f"\n{check_info['recommendation']}")
                        summary_file.write(f"\n{check_info['recommendation']}\n")
                        
                    if check_info["reference"]:
                        print(f"\n{check_info['reference']}")
                        summary_file.write(f"\n{check_info['reference']}\n")
                
                print("")  # Add blank line after details
                summary_file.write("\n")  # Add blank line to summary
        
        # Final success message about where results are stored
        print(f"\nDetailed results are available in {results_dir}/\n")
        summary_file.write(f"\nDetailed results are available in {results_dir}/\n")
    
    # Move debug log to final-results directory and create .tgz bundle
    import shutil
    import tarfile
    
    # Get absolute paths to handle WSL/venv environments correctly
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    
    # Search for debug log in multiple possible locations (WSL/venv compatibility)
    debug_log_search_paths = [
        os.path.join(script_dir, "nd_validation_debug.log"),  # Script directory
        os.path.join(cwd, "nd_validation_debug.log"),          # Current working directory
        os.path.abspath("nd_validation_debug.log")             # Relative to CWD
    ]
    
    debug_log_src = None
    for path in debug_log_search_paths:
        if os.path.exists(path):
            debug_log_src = path
            logger.info(f"Found debug log at: {debug_log_src}")
            break
    
    # Copy (not move) debug log to final-results directory
    # Using copy instead of move to ensure original remains if needed
    debug_log_dst = os.path.join(results_dir, "nd_validation_debug.log")
    
    if debug_log_src and os.path.exists(debug_log_src):
        try:
            shutil.copy2(debug_log_src, debug_log_dst)
            logger.info(f"Copied debug log to {debug_log_dst}")
        except Exception as e:
            logger.warning(f"Could not copy debug log: {str(e)}")
            # Try to at least create a placeholder with error info
            try:
                with open(debug_log_dst, 'w') as f:
                    f.write(f"Debug log could not be copied: {str(e)}\n")
                    f.write(f"Searched in: {', '.join(debug_log_search_paths)}\n")
            except:
                pass
    else:
        logger.warning(f"Debug log not found in any of: {', '.join(debug_log_search_paths)}")
        # Create a placeholder file to indicate the issue
        try:
            with open(debug_log_dst, 'w') as f:
                f.write("Debug log file was not found at script execution.\n")
                f.write(f"Searched in:\n")
                for path in debug_log_search_paths:
                    f.write(f"  - {path}\n")
        except Exception as e:
            logger.warning(f"Could not create placeholder debug log: {str(e)}")
    
    # Create timestamped .tgz bundle
    timestamp = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
    tgz_filename = f"nd-preupgrade-validation-results_{timestamp}.tgz"
    tgz_path = os.path.join(cwd, tgz_filename)
    
    try:
        with tarfile.open(tgz_path, "w:gz") as tar:
            # Add the entire final-results directory
            tar.add(results_dir, arcname="final-results")
        
        print(f"Results Bundle: {os.path.abspath(tgz_path)}\n")
        logger.info(f"Created results bundle: {tgz_path}")
        
    except Exception as e:
        logger.error(f"Failed to create results bundle: {str(e)}")
        logger.exception("Detailed traceback for bundle creation failure:")
        print(f"Warning: Could not create results bundle: {str(e)}\n")

def main():
    """Main function for the ND validation script"""
    
    # Set up logging first
    global logger
    logger = setup_logging()

    # Set up Ctrl+C handler for graceful shutdown
    def signal_handler(sig, frame):
        print("\n\n🛑 Interrupt received (Ctrl+C). Shutting down gracefully...")
        logger.warning("User interrupt (Ctrl+C) received. Initiating shutdown...")
        print("Please wait while we clean up active operations...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    logger.info("Signal handler registered for graceful shutdown")

    # Check environment dependencies first
    env_ready, missing_deps, install_instructions = check_environment()
    
    if not env_ready:
        print("\n⚠️  Missing Dependencies  ⚠️")
        print("=" * 40)
        print("The following dependencies are required but not found:")
        for dep in missing_deps:
            print("  - {}".format(dep))
        
        print("\nInstallation Instructions:")
        print("=" * 40)
        for instruction in install_instructions:
            print(instruction)
        
        # Check if running in GitBash on Windows to provide specific guidance
        if platform.system() == "Windows" and "MINGW" in os.environ.get("MSYSTEM", ""):
            print("\nYou appear to be running in GitBash on Windows.")
            print("This script requires sshpass which is not available in GitBash.")
            print("Options:")
            print("1. Use Windows Subsystem for Linux (WSL) instead")
            print("2. Run with --bash flag for limited Windows compatibility")
            print("   python nd-preupgrade-validation.py --bash")
        
        return 1

    # Continue with main function execution
    parser = argparse.ArgumentParser(description="Nexus Dashboard Pre-upgrade Validation Script")
    parser.add_argument("--ndip", help="IP address of the Nexus Dashboard")
    parser.add_argument("-p", "--password", help="Password for rescue-user")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging to console and preserve temp files")
    parser.add_argument("-b", "--bash", action="store_true", help="Run in GitBash/Windows mode (no sshpass)")
    parser.add_argument("--diagnose", action="store_true", help="Run diagnostic tests only (check Python interpreters and worker script execution)")
    
    args = parser.parse_args()
    
    print("Nexus Dashboard Pre-upgrade Validation Script")
    print(f"Running validation checks on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    # Get ND IP with validation
    nd_ip = args.ndip
    if not nd_ip:
        while True:
            nd_ip = input("Enter Nexus Dashboard IP address: ")
            if is_valid_ip(nd_ip):
                break
            else:
                print(f"{FAIL} Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.1)")
    else:
        # Also validate IP if provided via command line
        if not is_valid_ip(nd_ip):
            print(f"{FAIL} Invalid IP address format: {nd_ip}")
            print("Please enter a valid IPv4 address (e.g., 192.168.1.1)")
            return 1
    
    # Get password
    password = args.password
    if not password:
        password = getpass.getpass("Enter password for rescue-user: ")
    
    print()  # Add blank line
    
    # Create ND node manager
    node_manager = NDNodeManager(nd_ip, "rescue-user", password)
    
    try:
        # Connect to the Nexus Dashboard
        print(f"Connecting to Nexus Dashboard at {nd_ip}...")
        if not node_manager.connect():
            print(f"{FAIL} Failed to connect to Nexus Dashboard. Please check credentials and network connectivity.")
            return 1
        
        # Get version information (connection already established, so legacy mode is set if needed)
        logger.info("Getting Nexus Dashboard version")
        try:
            import subprocess
            
            # Use node_manager's SSH command builder which includes legacy mode if needed
            cmd = node_manager.build_ssh_command(nd_ip, "acs version") + " 2>/dev/null"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            version = None
            if process.returncode == 0:
                output = stdout.decode('utf-8')
                match = re.search(r'Nexus Dashboard\s+(\S+)', output)
                if match:
                    version = match.group(1)
                    print(f"Successfully connected to Nexus Dashboard at {nd_ip}")
                    print(f"Nexus Dashboard version: {version}")
            
        except Exception as e:
            logger.error(f"Error getting version: {str(e)}")
        
        # Check for version 4.1.1x - if detected, switch to root user
        # This applies to all 4.1.1 variants (4.1.1, 4.1.1a, 4.1.1b, 4.1.1g, etc.)
        if version and version.startswith('4.1.1'):
            print(f"\n{WARNING} Detected ND version {version} - this version requires root access to run")
            print(f"\nExecuting 'acs debug-token' to retrieve the root password token...")
            
            try:
                # Execute acs debug-token command
                token_cmd = node_manager.build_ssh_command(nd_ip, "acs debug-token") + " 2>/dev/null"
                process = subprocess.Popen(token_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    debug_token = stdout.decode('utf-8').strip()
                    # Remove any extra whitespace or newlines
                    debug_token = debug_token.split('\n')[-1].strip() if '\n' in debug_token else debug_token
                    
                    if debug_token:
                        print(f"\nRoot password token: {debug_token}")
                        print(f"\nPlease enter the root password for Nexus Dashboard.")
                        
                        # Prompt for root password
                        root_password = getpass.getpass("Enter root password: ")
                        
                        if root_password:
                            # Update node_manager to use root credentials
                            node_manager.username = "root"
                            node_manager.password = root_password
                            
                            # Test the root credentials
                            print(f"\nVerifying root credentials...")
                            test_cmd = node_manager.build_ssh_command(nd_ip, "echo 'Root access verified'") + " 2>/dev/null"
                            process = subprocess.Popen(test_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            stdout, stderr = process.communicate()
                            
                            if process.returncode == 0 and 'Root access verified' in stdout.decode('utf-8'):
                                print(f"{PASS} Successfully switched to root user")
                                print(f"All subsequent operations will use root credentials\n")
                                logger.info(f"Switched to root user for version 4.1.1g")
                            else:
                                print(f"{FAIL} Failed to verify root credentials. Please check the password.")
                                print(f"Error: {stderr.decode('utf-8')}")
                                return 1
                        else:
                            print(f"{FAIL} Root password is required for version 4.1.1")
                            return 1
                    else:
                        print(f"{FAIL} Failed to retrieve debug token")
                        logger.error(f"Empty debug token returned")
                        return 1
                else:
                    print(f"{FAIL} Failed to execute 'acs debug-token' command")
                    logger.error(f"acs debug-token failed: {stderr.decode('utf-8')}")
                    return 1
                    
            except Exception as e:
                print(f"{FAIL} Error retrieving debug token: {str(e)}")
                logger.exception(f"Error in debug token retrieval")
                return 1
        
        # Discover nodes
        print("Discovering Nexus Dashboard nodes...")
        nodes = node_manager.discover_nodes()
        
        if not nodes:
            print(f"{FAIL} No nodes found in the Nexus Dashboard cluster")
            return 1
        
        print(f"Found {len(nodes)} Nexus Dashboard nodes")
        print("---------------------------------------")
        for node in nodes:
            print(f"\t{node['name']} ({node['ip']})")
        print("---------------------------------------")
        
        # Check disk space on all nodes before proceeding
        print("\nChecking disk space on all nodes...")
        nodes_with_space_issues = []
        nodes_healthy = []
        
        for node in nodes:
            # Skip inactive nodes
            if node.get('status', '').lower() != 'active':
                logger.info(f"Skipping disk space check for inactive node {node['name']}")
                continue
            
            print(f"Checking {node['name']}...", end=" ")
            is_healthy, over_threshold_dirs, error_msg = node_manager.check_node_disk_space(node)
            
            if is_healthy:
                print(f"{PASS}")
                nodes_healthy.append(node['name'])
            else:
                print(f"{FAIL}")
                nodes_with_space_issues.append({
                    'node': node,
                    'directories': over_threshold_dirs,
                    'error': error_msg
                })
        
        # For versions below 4.1.1, check for large eventmonitoring log files
        nodes_with_large_logs = []
        if version and not version.startswith('4.1.1'):
            print("\nChecking for large eventmonitoring log files...")
            
            for node in nodes:
                # Skip inactive nodes
                if node.get('status', '').lower() != 'active':
                    logger.info(f"Skipping eventmonitoring check for inactive node {node['name']}")
                    continue
                
                # Skip nodes that already failed disk space check
                if any(issue['node']['name'] == node['name'] for issue in nodes_with_space_issues):
                    continue
                
                print(f"Checking {node['name']}...", end=" ")
                is_healthy, large_files, error_msg = node_manager.check_eventmonitoring_logs(node)
                
                if is_healthy:
                    print(f"{PASS}")
                else:
                    print(f"{FAIL}")
                    nodes_with_large_logs.append({
                        'node': node,
                        'large_files': large_files,
                        'error': error_msg
                    })
        
        # If any nodes have large log files, report them and exclude from validation
        if nodes_with_large_logs:
            print(f"\n{FAIL} Large Eventmonitoring Log Files Detected")
            print("="*80)
            print("The following nodes have eventmonitoring log files >= 1G:\n")
            
            for issue in nodes_with_large_logs:
                node = issue['node']
                large_files = issue['large_files']
                
                print(f"{node['name']} ({node['ip']}):")
                if large_files:
                    for file_size in large_files:
                        print(f"  • File size: {file_size}")
                else:
                    print(f"  • {issue['error']}")
                
                print(f"  {WARNING} Tech support will not be collected for {node['name']}")
                print(f"  Recommendation: Contact TAC to help resolve this issue before")
                print(f"                  collecting tech support on {node['name']}\n")
            
            # Filter out nodes with large log files from the nodes list
            failed_node_names = [issue['node']['name'] for issue in nodes_with_large_logs]
            nodes = [node for node in nodes if node['name'] not in failed_node_names]
            
            if not nodes:
                print(f"\n{FAIL} All nodes have large eventmonitoring log files. Cannot proceed with validation.")
                print("Please resolve the eventmonitoring log issues and rerun the script.\n")
                return 1
            
            print(f"{WARNING} Proceeding with validation on {len(nodes)} node(s) that passed the eventmonitoring check:")
            for node in nodes:
                print(f"  - {node['name']} ({node['ip']})")
            
            # Ask user for confirmation
            while True:
                choice = input(f"\nDo you want to continue with validation on {len(nodes)} node(s)? (y/n): ").lower().strip()
                if choice in ['y', 'yes']:
                    print("Proceeding with nodes that passed eventmonitoring check...")
                    # Update node_manager to use only healthy nodes
                    node_manager.nodes = nodes
                    break
                elif choice in ['n', 'no']:
                    print("Validation cancelled by user.")
                    return 0
                else:
                    print("Please enter 'y' for yes or 'n' for no.")
            print()
        
        # If any nodes have space issues, report them and exclude from validation
        if nodes_with_space_issues:
            print(f"\n{FAIL} Disk Space Issues Detected")
            print("="*80)
            print("The following nodes have directories with usage >= 80%:\n")
            
            for issue in nodes_with_space_issues:
                node = issue['node']
                directories = issue['directories']
                
                print(f"{node['name']} ({node['ip']}):")
                if directories:
                    for mount_point, usage_pct in directories:
                        print(f"  • {mount_point}: {usage_pct:.0f}% full")
                else:
                    print(f"  • {issue['error']}")
                
                print(f"  {WARNING} Script will not run on {node['name']}")
                print(f"  Recommendation: Contact TAC to help clear these directories before")
                print(f"                  rerunning the script against {node['name']}\n")
            
            # Filter out nodes with space issues from the nodes list
            failed_node_names = [issue['node']['name'] for issue in nodes_with_space_issues]
            nodes = [node for node in nodes if node['name'] not in failed_node_names]
            
            if not nodes:
                print(f"\n{FAIL} All nodes have disk space issues. Cannot proceed with validation.")
                print("Please resolve the disk space issues and rerun the script.\n")
                return 1
            
            print(f"{WARNING} Proceeding with validation on {len(nodes)} node(s) that passed disk space check:")
            for node in nodes:
                print(f"  - {node['name']} ({node['ip']})")
            
            # Ask user for confirmation
            while True:
                choice = input(f"\nDo you want to continue with validation on {len(nodes)} node(s)? (y/n): ").lower().strip()
                if choice in ['y', 'yes']:
                    print("Proceeding with nodes that passed disk space check...")
                    # Update node_manager to use only healthy nodes
                    node_manager.nodes = nodes
                    break
                elif choice in ['n', 'no']:
                    print("Validation cancelled by user.")
                    return 0
                else:
                    print("Please enter 'y' for yes or 'n' for no.")
            print()
        
        # Check for inactive nodes and get user confirmation
        inactive_nodes = [node for node in nodes if node.get('status', '').lower() != 'active']
        active_nodes = [node for node in nodes if node.get('status', '').lower() == 'active']
        
        if inactive_nodes:
            print(f"\n{WARNING} Inactive Nodes Detected")
            print("="*50)
            print("The following Nexus Dashboard nodes are currently INACTIVE:")
            for node in inactive_nodes:
                status = node.get('status', 'Unknown')
                print(f"  - {node['name']} ({node['ip']}) - Status: {status}")
            
            print(f"\nActive nodes available for validation: {len(active_nodes)}")
            for node in active_nodes:
                print(f"  - {node['name']} ({node['ip']})")
            
            if not active_nodes:
                print(f"\n{FAIL} No active nodes available for validation. Cannot proceed.")
                return 1
            
            print(f"\n{WARNING} Inactive nodes will be skipped during validation operations.")
            print("Tech support operations and validations will only run on active nodes.")
            
            while True:
                choice = input(f"\nDo you want to continue with validation on {len(active_nodes)} active node(s)? (y/n): ").lower().strip()
                if choice in ['y', 'yes']:
                    print("Proceeding with active nodes only...")
                    # Update the node_manager to use only active nodes
                    node_manager.nodes = active_nodes
                    nodes = active_nodes
                    break
                elif choice in ['n', 'no']:
                    print("Validation cancelled by user.")
                    return 0
                else:
                    print("Please enter 'y' for yes or 'n' for no.")
        else:
            print(f"\n{PASS} All {len(nodes)} nodes are active and have healthy disk space (<80% usage).")
            print(f"{PASS} All nodes are ready for validation.")
            active_nodes = nodes
        
        # Run diagnostic mode if requested
        if args.diagnose:
            print("\n" + "="*80)
            print("  DIAGNOSTIC MODE")
            print("="*80)
            return run_diagnostic_mode(node_manager, nodes)
        
        # Check system resources for optimal concurrency
        resources = check_system_resources()
        max_concurrent = resources.get("recommended_parallelism", 2)
        
        # Only display resource info when more than one node is detected
        if len(nodes) > 1:
            print(f"\nSystem resource assessment:")
            print(f"  CPU cores: {resources.get('cpu_count', 'unknown')}")
            print(f"  Memory: {resources.get('memory_gb', 'unknown')} GB")
            print(f"  Current load: {resources.get('load_5min', 'unknown')}")
            print(f"  Recommended concurrent nodes: {max_concurrent}")
            if len(nodes) > max_concurrent:
                print(f"  Note: Nodes will be processed in {math.ceil(len(nodes)/max_concurrent)} batches for optimal performance")
            print()
        
        # Normal mode - ask about tech support generation
        print("Do you want to generate new tech supports for analysis?")
        print("1. Generate new tech supports for analysis")
        print("2. Use existing tech supports on all nodes")
        
        tech_choice = input("\nEnter your choice (1/2): ")
        
        # Store skipped nodes information for final report
        skipped_nodes_info = {
            'disk_space_issues': nodes_with_space_issues if nodes_with_space_issues else [],
            'large_log_files': nodes_with_large_logs if nodes_with_large_logs else []
        }
        
        # Process all nodes - resource-optimized
        # Save the results to ensure we can access debug_data after the report is generated
        results = process_all_nodes(node_manager, tech_choice, args.debug, skipped_nodes_info)
        
        # Display debug mode warning at the very end, after the report
        if args.debug and results and "_debug_info" in results:
            # Get debug info from results
            debug_info = results["_debug_info"]
            # Only show warning if there were successful nodes
            if debug_info["successful_nodes"]:
                warning_message = f"\n{WARNING} Debug mode enabled: Temporary files were NOT removed from nodes."
                warning_message += f"\nTemporary files remain in {debug_info['base_dir']} on each node for debugging purposes."
                print(warning_message)
        
        return 0 if results else 1
        
    except Exception as e:
        print(f"{FAIL} An error occurred: {str(e)}")
        logger.exception("Unhandled exception in main")
        return 1
    finally:
        # Disconnect from ND
        node_manager.disconnect()

def run_diagnostic_mode(node_manager, nodes):
    """Run diagnostic tests to identify issues with worker script execution"""
    print("Running diagnostic tests on all nodes...")
    print("This will help identify issues with Python interpreters and worker script execution.\n")
    
    script_manager = WorkerScriptManager(node_manager)
    results = {}
    
    # Load the worker script content first
    try:
        worker_script_content = get_worker_script_content()
    except Exception as e:
        print(f"{FAIL} Failed to load worker script: {str(e)}")
        return 1
    
    for node in nodes:
        print(f"Diagnosing node {node['name']} ({node['ip']})...")
        node_results = {
            'python_interpreters': [],
            'worker_deployment': False,
            'test_execution': False,
            'errors': []
        }
        
        try:
            # Test Python interpreters
            interpreters = script_manager.check_python_availability(node)
            node_results['python_interpreters'] = interpreters
            
            if interpreters:
                print(f"  {PASS} Found {len(interpreters)} Python interpreter(s):")
                for interp in interpreters:
                    print(f"    - {interp['interpreter']}: {interp['version']} at {interp['path']}")
            else:
                print(f"  {FAIL} No Python interpreters found")
                node_results['errors'].append("No Python interpreters found")
            
            # Test worker script deployment
            print(f"  Testing worker script deployment...")
            deployed_script_path = script_manager.deploy_worker_script(node, worker_script_content)
            if deployed_script_path:
                node_results['worker_deployment'] = True
                print(f"  {PASS} Worker script deployed successfully at {deployed_script_path}")
                
                # Test a simple Python execution
                print(f"  Testing Python execution...")
                import subprocess
                import shlex
                cmd = node_manager.build_ssh_command(node['ip'], "cd /tmp/ndpreupgradecheck && python3 -c 'print(\\\"Python test successful\\\")' 2>&1 || python -c 'print(\\\"Python test successful\\\")' 2>&1 || python2 -c 'print(\\\"Python test successful\\\")' 2>&1")
                
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                output = stdout.decode('utf-8') + stderr.decode('utf-8')
                
                if "Python test successful" in output:
                    node_results['test_execution'] = True
                    print(f"  {PASS} Python execution test passed")
                else:
                    print(f"  {FAIL} Python execution test failed: {output}")
                    node_results['errors'].append(f"Python execution failed: {output}")
                
                # Test basic worker script syntax
                print(f"  Testing worker script syntax...")
                syntax_cmd = node_manager.build_ssh_command(node['ip'], "cd /tmp/ndpreupgradecheck && python3 -m py_compile nd_worker.py 2>&1 || python -m py_compile nd_worker.py 2>&1 || python2 -m py_compile nd_worker.py 2>&1")
                
                process = subprocess.Popen(syntax_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                syntax_output = stdout.decode('utf-8') + stderr.decode('utf-8')
                
                if not syntax_output.strip() or "Compiled successfully" in syntax_output:
                    print(f"  {PASS} Worker script syntax check passed")
                else:
                    print(f"  {FAIL} Worker script syntax issues: {syntax_output}")
                    node_results['errors'].append(f"Syntax error: {syntax_output}")
                
            else:
                print(f"  {FAIL} Worker script deployment failed")
                node_results['errors'].append("Worker script deployment failed")
        
        except Exception as e:
            error_msg = f"Diagnostic error: {str(e)}"
            print(f"  {FAIL} {error_msg}")
            node_results['errors'].append(error_msg)
        
        results[node['name']] = node_results
        print()
    
    # Summary
    print("="*80)
    print("DIAGNOSTIC SUMMARY")
    print("="*80)
    
    all_good = True
    for node_name, result in results.items():
        print(f"\nNode {node_name}:")
        
        if result['python_interpreters']:
            print(f"  {PASS} Python interpreters available: {len(result['python_interpreters'])}")
        else:
            print(f"  {FAIL} No Python interpreters found")
            all_good = False
        
        if result['worker_deployment']:
            print(f"  {PASS} Worker script deployment successful")
        else:
            print(f"  {FAIL} Worker script deployment failed")
            all_good = False
        
        if result['test_execution']:
            print(f"  {PASS} Python execution test passed")
        else:
            print(f"  {FAIL} Python execution test failed")
            all_good = False
        
        if result['errors']:
            print(f"  {FAIL} Errors detected:")
            for error in result['errors']:
                print(f"    - {error}")
            all_good = False
    
    print("\n" + "="*80)
    if all_good:
        print(f"{PASS} All diagnostic tests passed!")
        print("Your environment should be ready to run the worker scripts.")
    else:
        print(f"{FAIL} Some diagnostic tests failed.")
        print("Please address the issues above before running the full validation.")
    
    print("="*80)
    return 0 if all_good else 1

if __name__ == "__main__":
    sys.exit(main())
    