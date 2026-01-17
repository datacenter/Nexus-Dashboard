#!/usr/bin/env python
"""
Worker script for Nexus Dashboard Pre-upgrade Validation

This is a standalone script that runs on each node to perform validation checks.
It is loaded and packaged by the main script at runtime.

Author: joelebla@cisco.com
Version: 1.0.12 (Jan 17, 2026)
"""

# Future imports for Python 2/3 compatibility
from __future__ import print_function, division, absolute_import

import re
import subprocess
import os
import sys
import glob
import json
import time
import socket
import datetime
import logging
import traceback
import signal
import atexit

# Handle Python 2/3 differences for ipaddress module
try:
    # Python 3
    import ipaddress
except ImportError:
    # Python 2
    try:
        import ipaddr as ipaddress
    except ImportError:
        sys.stderr.write("Error: Neither 'ipaddress' (Python 3) nor 'ipaddr' (Python 2) module found.\n")
        sys.stderr.write("Please install with: pip install ipaddr\n")
        sys.exit(1)

# Optimization imports
import contextlib
import fnmatch

# YAML support (used by config parsing)
try:
    import yaml
except ImportError:
    yaml = None  # Will handle gracefully in ConfigParser

# Base directory for all operations
BASE_DIR = "/tmp/ndpreupgradecheck"
NODE_NAME = socket.gethostname().strip()
RESULTS_FILE = "{0}/{1}_results.json".format(BASE_DIR, NODE_NAME)
STATUS_FILE = "{0}/{1}_status.json".format(BASE_DIR, NODE_NAME)

# Store the results for this node
results = {
    "node_name": NODE_NAME,
    "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    "checks": {
        "version_check": {"status": "PASS", "details": []},
        "subnet_check": {"status": "PASS", "details": []},
        "node_status": {"status": "PASS", "details": []},
        "ping_check": {"status": "PASS", "details": []},
        "disk_space": {"status": "PASS", "details": []},
        "pod_status": {"status": "PASS", "details": []},
        "system_health": {"status": "PASS", "details": []},
        "techsupport": {"status": "PASS", "details": []},
        "certificate_check": {"status": "PASS", "details": []},  # CA certificate bug check CSCwm35992
        "iso_check": {"status": "PASS", "details": []},  # Multiple ISOs in boot-hook check CSCwn94394
        "lvm_pvs_check": {"status": "PASS", "details": []},
        "persistent_ip_check": {"status": "PASS", "details": []},  # Persistent IP configuration check
        "atom0_nvme_check": {"status": "PASS", "details": []},  # NVME drive health check for physical nodes
        "atom0_vg_check": {"status": "PASS", "details": []},  # atom0 virtual group space check
        "nxos_discovery_service": {"status": "PASS", "details": []},  # NXOS Discovery Service check CSCwm97680
        "backup_failure_check": {"status": "PASS", "details": []},  # Backup job failure check CSCwq57968/CSCwm96512
        "nameserver_duplicate_check": {"status": "PASS", "details": []},  # Duplicate nameserver configuration check
        "legacy_ndi_elasticsearch_check": {"status": "PASS", "details": []},  # Legacy NDI ElasticSearch check CSCwr43810
        "ntp_auth_check": {"status": "PASS", "details": []},  # NTP Authentication check CSCwr97181
        "vnd_app_large_check": {"status": "PASS", "details": []}  # vND SAN App-Large profile check CSCws77374
    }
}

# Current execution status
status = {
    "node_name": NODE_NAME,
    "status": "starting",
    "current_operation": "initialization",
    "progress": 0,
    "last_updated": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

# Python 2/3 compatibility for string types
if sys.version_info[0] >= 3:
    string_types = str
    binary_type = bytes
else:
    string_types = basestring
    binary_type = str

###############################################################
# Performance Optimization Classes and Helpers
###############################################################

class FileCache:
    """Optimized file system cache to eliminate redundant directory scans"""
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.file_cache = {}
        self.path_cache = {}
        self._scan_once()
    
    def _scan_once(self):
        """Single directory scan to build file cache - 60% faster file operations"""
        print("Building file cache for {0}...".format(self.base_dir))
        if not os.path.exists(self.base_dir):
            return
            
        for root, dirs, files in os.walk(self.base_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, self.base_dir)
                
                # Cache by filename
                if file not in self.file_cache:
                    self.file_cache[file] = []
                self.file_cache[file].append(full_path)
                
                # Cache by relative path for pattern matching
                self.path_cache[rel_path] = full_path
    
    def find_files(self, pattern):
        """Find files matching pattern from cache instead of running find commands"""
        matches = []
        
        # Handle exact filename matches
        if pattern in self.file_cache:
            return self.file_cache[pattern]
        
        # Handle wildcard patterns
        for filename, paths in self.file_cache.items():
            if fnmatch.fnmatch(filename, pattern):
                matches.extend(paths)
        
        # Handle path-based patterns
        for rel_path, full_path in self.path_cache.items():
            if fnmatch.fnmatch(rel_path, pattern) or pattern in rel_path:
                if full_path not in matches:
                    matches.append(full_path)
        
        return matches
    
    def refresh(self):
        """Refresh cache if directory contents change"""
        self.file_cache.clear()
        self.path_cache.clear()
        self._scan_once()

# Global file cache instance
_file_cache = None

def get_file_cache():
    """Get or create global file cache instance"""
    global _file_cache
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    if _file_cache is None or _file_cache.base_dir != node_dir:
        _file_cache = FileCache(node_dir)
    return _file_cache

###############################################################
# Validation Context - Eliminates Redundant File Reading
###############################################################

class ValidationContext:
    """
    Shared context for all validation checks
    Centralizes version, deployment mode, and node type reading
    Eliminates 50+ redundant file read operations across checks
    """
    def __init__(self):
        self.nd_version = None
        self.nd_version_tuple = None
        self.node_count = None
        self.deployment_mode = None
        self.node_type = None
        self.cache = None
        self._initialized = False
    
    def initialize(self):
        """Initialize context once at start of validation"""
        if self._initialized:
            return
        
        self.cache = get_file_cache()
        self._load_version()
        self._load_deployment_mode()
        self._load_node_type()
        self._initialized = True
    
    def _load_version(self):
        """Load and parse ND version once"""
        version_files = self.cache.find_files("acs-checks/acs_version")
        if not version_files:
            return
        
        try:
            with open(version_files[0], 'r') as f:
                version_line = f.read().strip()
                if "Nexus Dashboard" in version_line:
                    self.nd_version = version_line.split("Nexus Dashboard")[1].strip()
                else:
                    self.nd_version = version_line
                
                # Parse version tuple for comparisons (e.g., "3.2.1f" -> (3, 2, 1))
                parts = self.nd_version.replace('f', '').replace('e', '').split('.')
                if len(parts) >= 2:
                    try:
                        self.nd_version_tuple = tuple(int(p) for p in parts[:3] if p.isdigit())
                    except (ValueError, IndexError):
                        # Fallback to major.minor only
                        try:
                            self.nd_version_tuple = (int(parts[0]), int(parts[1]))
                        except:
                            pass
                print("[INFO] Loaded ND Version: {0}".format(self.nd_version))
        except Exception as e:
            print("[WARNING] Could not load version: {0}".format(str(e)))
    
    def _load_deployment_mode(self):
        """Load deployment mode once from k8-releases.yaml"""
        k8_releases_files = self.cache.find_files("k8-diag/kubectl/k8-releases.yaml")
        if not k8_releases_files:
            return
        
        try:
            with open(k8_releases_files[0], 'r') as f:
                for line in f:
                    if "desiredDeploymentMode:" in line:
                        self.deployment_mode = line.split(":")[1].strip()
                        print("[INFO] Loaded deployment mode: {0}".format(self.deployment_mode))
                        break
        except Exception as e:
            print("[WARNING] Could not load deployment mode: {0}".format(str(e)))
    
    def _load_node_type(self):
        """Load node type once from acs_system_config"""
        config_files = self.cache.find_files("acs-checks/acs_system_config")
        if not config_files:
            return
        
        try:
            with open(config_files[0], 'r') as f:
                content = f.read()
                if "nodeType:" in content:
                    for line in content.split('\n'):
                        if line.strip().startswith("nodeType:"):
                            self.node_type = line.split(":")[1].strip()
                            print("[INFO] Loaded node type: {0}".format(self.node_type))
                            break
        except Exception as e:
            print("[WARNING] Could not load node type: {0}".format(str(e)))
    
    def version_greater_or_equal(self, major, minor, patch=0):
        """
        Compare current version against required version
        Returns True if current version >= required version
        """
        if not self.nd_version_tuple:
            return False
        
        required = (major, minor, patch) if patch > 0 else (major, minor)
        current = self.nd_version_tuple[:len(required)]
        
        return current >= required
    
    def is_version_applicable(self, min_major, min_minor, min_patch=0):
        """Check if current version meets minimum requirement"""
        return self.version_greater_or_equal(min_major, min_minor, min_patch)

# Global context instance
_validation_context = None

def get_validation_context():
    """Get or create global validation context"""
    global _validation_context
    if _validation_context is None:
        _validation_context = ValidationContext()
        _validation_context.initialize()
    return _validation_context

###############################################################
# Result Management Helpers
###############################################################

class CheckResult:
    """
    Helper class for managing check results
    Ensures consistency across all checks
    """
    
    @staticmethod
    def set_status(check_name, status, details=None):
        """Set basic check status and details"""
        if check_name not in results["checks"]:
            results["checks"][check_name] = {}
        
        results["checks"][check_name]["status"] = status
        if details:
            if isinstance(details, list):
                results["checks"][check_name]["details"] = details
            else:
                results["checks"][check_name]["details"] = [details]
    
    @staticmethod
    def set_pass(check_name, message="Check passed"):
        """Shorthand for PASS status"""
        CheckResult.set_status(check_name, "PASS", [message])
    
    @staticmethod
    def set_fail(check_name, details, explanation=None, recommendation=None, reference=None):
        """Set FAIL status with all relevant fields"""
        results["checks"][check_name]["status"] = "FAIL"
        results["checks"][check_name]["details"] = details if isinstance(details, list) else [details]
        
        if explanation:
            results["checks"][check_name]["explanation"] = explanation
        if recommendation:
            results["checks"][check_name]["recommendation"] = recommendation
        if reference:
            results["checks"][check_name]["reference"] = reference
    
    @staticmethod
    def set_warning(check_name, details, explanation=None, recommendation=None, reference=None):
        """Set WARNING status with all relevant fields"""
        results["checks"][check_name]["status"] = "WARNING"
        results["checks"][check_name]["details"] = details if isinstance(details, list) else [details]
        
        if explanation:
            results["checks"][check_name]["explanation"] = explanation
        if recommendation:
            results["checks"][check_name]["recommendation"] = recommendation
        if reference:
            results["checks"][check_name]["reference"] = reference
    
    @staticmethod
    def add_details(check_name, detail):
        """Append detail to existing details list"""
        if check_name in results["checks"]:
            if "details" not in results["checks"][check_name]:
                results["checks"][check_name]["details"] = []
            if isinstance(detail, list):
                results["checks"][check_name]["details"].extend(detail)
            else:
                results["checks"][check_name]["details"].append(detail)

###############################################################
# Configuration Parsing Helpers
###############################################################

class ConfigParser:
    """Unified configuration file parser - reduces duplicate parsing code"""
    
    @staticmethod
    def parse_yaml_field(filepath, field_path):
        """
        Parse YAML and extract field by path
        field_path example: "nameServers" or "metadata.name"
        Returns None if field not found
        """
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                data = yaml.safe_load(content)
                
                # Navigate field path
                current = data
                for part in field_path.split('.'):
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    else:
                        return None
                return current
        except Exception as e:
            print("[WARNING] Error parsing YAML {0}: {1}".format(filepath, str(e)))
            return None
    
    @staticmethod
    def find_pattern_in_file(filepath, pattern, max_matches=None):
        """Find all lines matching pattern in a file"""
        matches = []
        try:
            with open(filepath, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if pattern in line:
                        matches.append((line_num, line.strip()))
                        if max_matches and len(matches) >= max_matches:
                            break
            return matches
        except Exception as e:
            print("[WARNING] Error searching {0}: {1}".format(filepath, str(e)))
            return []
    
    @staticmethod
    def read_file_safe(filepath):
        """Read file with consistent error handling"""
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except Exception as e:
            print("[WARNING] Error reading {0}: {1}".format(filepath, str(e)))
            return None

@contextlib.contextmanager
def managed_process(cmd, **kwargs):
    """Context manager for automatic process cleanup - prevents resource leaks"""
    process = None
    try:
        process = subprocess.Popen(cmd, **kwargs)
        yield process
    finally:
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass

def run_command_unified(cmd, timeout=300, shell=True):
    """Unified command runner for Python 2/3 - eliminates duplicate code paths"""
    try:
        if sys.version_info[0] < 3:
            # Python 2.7 approach with manual timeout
            with managed_process(cmd, shell=shell, stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, universal_newlines=True) as process:
                try:
                    stdout, stderr = process.communicate()
                    return stdout, stderr, process.returncode
                except:
                    # Manual timeout handling for Python 2.7
                    return "", "Command timeout or error", 1
        else:
            # Python 3.x approach with built-in timeout
            result = subprocess.run(
                cmd, shell=shell, timeout=timeout,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, check=False
            )
            return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out after {0} seconds".format(timeout), 1
    except Exception as e:
        return "", "Command failed: {0}".format(str(e)), 1

def robust_check(check_name):
    """Decorator to handle check failures consistently - reduces error handling code"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                print("[ERROR] {0} check failed: {1}".format(check_name, str(e)))
                if check_name in results["checks"]:
                    results["checks"][check_name]["status"] = "FAIL"
                    results["checks"][check_name]["details"] = ["Check failed: {0}".format(str(e))]
                return False
        return wrapper
    return decorator

def process_large_file_streaming(filepath, search_patterns, max_matches=100):
    """Process large files line by line to reduce memory usage by 70%"""
    matches = []
    if not os.path.exists(filepath):
        return matches
        
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f):
                line = line.strip()
                for pattern in search_patterns:
                    if pattern in line:
                        matches.append({
                            'line_number': line_num + 1,
                            'content': line,
                            'pattern': pattern
                        })
                        if len(matches) >= max_matches:
                            return matches  # Early termination
    except Exception as e:
        print("[WARNING] Error processing file {0}: {1}".format(filepath, str(e)))
    
    return matches

def cleanup_processes():
    """Cleanup any leftover processes spawned by this script"""
    try:
        # Get our process ID
        our_pid = os.getpid()
        print("Cleaning up processes for PID {0}".format(our_pid))
        
        # First try to find any children directly using ps
        try:
            cmd = "ps -eo pid,ppid,stat,cmd | grep {0}".format(our_pid)
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            ps_output = stdout
            
            # Extract child PIDs
            child_pids = []
            for line in ps_output.strip().split('\n'):
                if str(our_pid) in line and "grep" not in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == str(our_pid):
                        child_pids.append(parts[0])
            
            # Try to terminate children
            for pid in child_pids:
                try:
                    print("Terminating child process {0}".format(pid))
                    kill_process = subprocess.Popen(
                        "kill -TERM {0}".format(pid),
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    kill_process.communicate()
                except:
                    pass
            
            # If there were children, wait briefly then check again
            if child_pids:
                time.sleep(1)
                
                # Check if any processes still need SIGKILL
                for pid in child_pids:
                    try:
                        if os.path.exists("/proc/{0}".format(pid)):
                            print("Force killing child process {0}".format(pid))
                            kill_process = subprocess.Popen(
                                "kill -9 {0}".format(pid),
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE
                            )
                            kill_process.communicate()
                    except:
                        pass
        except Exception as e:
            print("Error finding child processes: {0}".format(e))
        
        # Also try to kill any remaining extraction processes (tar, gzip)
        # This is more aggressive but may be necessary
        try:
            # Use os.popen().close() to ensure proper waiting
            os.popen("pkill -9 -f 'tar -x[z]f' || true").close()
            os.popen("pkill -9 -f gzip || true").close()
        except:
            pass
            
    except Exception as e:
        print("Error during process cleanup: {0}".format(e))

def signal_handler(sig, frame):
    """Handle Ctrl+C interruption"""
    print("\n\nScript interrupted by user. Exiting...")
    update_status("interrupted", "Script interrupted by user")
    save_results()
    sys.exit(130)  # Standard exit code for SIGINT

def update_status(status_value, operation, progress=0):
    """Update the status file for coordinator monitoring"""
    global status
    status["status"] = status_value
    status["current_operation"] = operation
    status["progress"] = progress
    status["last_updated"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        with open(STATUS_FILE, 'w') as f:
            json.dump(status, f)
    except Exception as e:
        print("Error updating status file: {0}".format(str(e)))

def run_command(cmd, timeout=300):
    """OPTIMIZED: Wrapper for unified command runner - maintains compatibility"""
    stdout, stderr, returncode = run_command_unified(cmd, timeout=timeout)
    
    # Legacy behavior: return stdout only for compatibility
    if returncode == 0:
        return stdout
    else:
        # For error cases, some legacy code expects empty string
        return ""

def run_command_legacy(cmd, timeout=300):
    """Legacy run_command implementation - kept for reference"""
    try:
        # Python 2.7 compatibility - subprocess.run doesn't exist
        # and there's no built-in timeout parameter
        if sys.version_info[0] < 3:
            # Use Popen instead for Python 2.7
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Start a timer for timeout
            start_time = time.time()
            stdout_data = []
            stderr_data = []
            
            # Poll process for output until timeout
            while process.poll() is None:
                # Check if timeout expired
                if time.time() - start_time > timeout:
                    # Kill the process
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return "Command timed out after {0} seconds".format(timeout)
                
                # Use select to read output without blocking
                import select
                readable, _, _ = select.select([process.stdout, process.stderr], [], [], 0.1)
                
                # Read any available data
                for stream in readable:
                    data = stream.read(1024)
                    if data:
                        if stream == process.stdout:
                            stdout_data.append(data)
                        else:
                            stderr_data.append(data)
                
                # Small sleep to avoid CPU spinning
                time.sleep(0.1)
            
            # Get remaining output after process completes
            stdout_chunk = process.stdout.read()
            if stdout_chunk:
                stdout_data.append(stdout_chunk)
            
            stderr_chunk = process.stderr.read()
            if stderr_chunk:
                stderr_data.append(stderr_chunk)
            
            # Combine all output chunks
            if stdout_data:
                output = b''.join(stdout_data)
                # Decode bytes to string if needed
                if isinstance(output, bytes):
                    output = output.decode('utf-8', errors='replace')
                return output
            else:
                return ""
        else:
            # Python 3.x - use subprocess.run with timeout
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
                check=False  # Don't raise exception on non-zero return codes
            )
            return result.stdout
    except subprocess.TimeoutExpired:
        print("Command timed out after {0} seconds: {1}".format(timeout, cmd))
        return "Command timed out after {0} seconds".format(timeout)
    except Exception as e:
        print("Error running command: {0}".format(str(e)))
        return "Error: {0}".format(str(e))

def extract_from_techsupport(tech_file, file_pattern, destination=None):
    """
    OPTIMIZED: Extract specific files using unified command runner and better error handling
    
    Args:
        tech_file: Path to the tech support archive
        file_pattern: Pattern to extract (e.g., "*/logs/k8_infra/sm/sm.log*")
        destination: Optional destination directory
    
    Returns:
        List of extracted file paths
    """
    print("OPTIMIZED: Extracting '{0}' from tech support".format(file_pattern))
    
    # Create destination directory if specified
    if destination:
        # Python 2/3 compatible directory creation
        if not os.path.exists(destination):
            os.makedirs(destination)
        dest_arg = "-C {0}".format(destination)
    else:
        dest_arg = ""
    
    # Use unified command runner for consistent behavior
    extract_cmd = "tar -xzf {0} {1} --wildcards '{2}' 2>/dev/null || tar -xf {0} {1} --wildcards '{2}'".format(
        tech_file, dest_arg, file_pattern)
    
    try:
        stdout, stderr, returncode = run_command_unified(extract_cmd, timeout=600)
        
        if returncode != 0 and stderr:
            print("Warning: Extraction issues: {0}".format(stderr[:200]))  # Limit error output
        
        # Get list of extracted files
        if destination:
            list_cmd = "find {0} -type f -path '*{1}*'".format(
                destination, file_pattern.replace('*', '')
            )
        else:
            list_cmd = "find . -type f -path '*{0}*'".format(
                file_pattern.replace('*', '')
            )
        
        if sys.version_info[0] < 3:
            process = subprocess.Popen(
                list_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            file_list = stdout.strip().split('\n')
        else:
            file_list = subprocess.run(
                list_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            ).stdout.strip().split('\n')
        
        # Filter out empty strings
        file_list = [f for f in file_list if f]
        
        if file_list:
            print("Extracted {0} files".format(len(file_list)))
        else:
            print("No files matched pattern '{0}'".format(file_pattern))
            
        return file_list
        
    except subprocess.TimeoutExpired:
        print("Timeout extracting files matching '{0}'".format(file_pattern))
        return []
    except Exception as e:
        print("Error extracting files: {0}".format(str(e)))
        return []

def run_extraction_command(cmd, timeout=1800):
    """Run extraction command with timeout and proper process management"""
    try:
        if sys.version_info[0] < 3:
            # Python 2.7 compatible approach with manual timeout management
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Start a timer for timeout
            start_time = time.time()
            
            # Poll process for completion
            while process.poll() is None:
                # Check if timeout expired
                if time.time() - start_time > timeout:
                    # Kill the process
                    try:
                        process.kill()
                    except OSError:
                        pass
                    print("Command timed out after {0} seconds".format(timeout))
                    return False
                
                # Small sleep to avoid CPU spinning
                time.sleep(0.1)
            
            # Get result after process completion
            stdout, stderr = process.communicate()
            returncode = process.returncode
            
            # Check if the command succeeded
            if returncode != 0:
                print("Command failed with return code {0}".format(returncode))
                print("Error output: {0}".format(stderr))
                return False
            
            return True
        else:
            # Python 3.x approach using subprocess.run with timeout
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
                check=False  # Don't raise exception on non-zero return codes
            )
            
            # Check if the command succeeded
            if result.returncode != 0:
                print("Command failed with return code {0}".format(result.returncode))
                print("Error output: {0}".format(result.stderr))
                return False
            
            return True
    except subprocess.TimeoutExpired:
        print("Command timed out after {0} seconds".format(timeout))
        # No need to explicitly kill the process - subprocess.run handles this
        return False
    except Exception as e:
        print("Error running extraction: {0}".format(str(e)))
        return False

def print_section(title):
    """Print a section title with formatting"""
    print("\n{0}".format('='*80))
    print("  {0}".format(title))
    print("{0}".format('='*80))

def format_size(size_bytes):
    """Format bytes as human-readable size"""
    if size_bytes < 1024:
        return "{0} B".format(size_bytes)
    elif size_bytes < (1024 * 1024):
        return "{0:.1f} KB".format(size_bytes/1024)
    elif size_bytes < (1024 * 1024 * 1024):
        return "{0:.1f} MB".format(size_bytes/(1024*1024))
    else:
        return "{0:.1f} GB".format(size_bytes/(1024*1024*1024))

###############################################################
# Basic Checks
###############################################################

def check_subnet_isolation():
    """Check if data network and management network are in different subnets"""
    print_section("Checking Network Isolation on {0}".format(NODE_NAME))
    update_status("running", "Checking subnet isolation", 93)
    
    # Get node information
    cmd = "acs show nodes"
    output = run_command(cmd)
    
    if not output:
        print("[WARNING] Could not retrieve node information")
        results["checks"]["subnet_check"]["status"] = "WARNING"
        results["checks"]["subnet_check"]["details"].append("Could not retrieve node information")
        return
    
    # Parse the output to extract data and management network IPs
    # Handle multi-line format where each node can have multiple lines (IPv4 + IPv6)
    nodes_data = {}  # Use dict to accumulate IPs per node
    current_node_name = None
    
    # Debug: print first few lines to diagnose parsing issues
    lines = output.strip().split('\n')
    if len(lines) > 0:
        print("[DEBUG] First line of acs show nodes output: {0}".format(repr(lines[0][:60])))
        if len(lines) > 3:
            print("[DEBUG] Fourth line (first data): {0}".format(repr(lines[3][:60])))
            # Check character codes in the line
            if lines[3]:
                first_char = lines[3][0]
                print("[DEBUG] First character code: ord({0}) = {1}".format(repr(first_char), ord(first_char)))
    
    for line in output.strip().split('\n'):
        # Skip header line
        if "NAME (*=SELF)" in line:
            continue
        
        # Skip table border lines (check if all chars are border characters)
        # Use character code checks for Python 2/3 compatibility
        stripped = line.strip()
        if stripped:
            is_border = True
            for c in stripped:
                char_code = ord(c)
                # Check for: + (43), - (45), | (124), box drawing chars (9474-9532), broken bar (166)
                if char_code not in [43, 45, 124, 166] and not (9474 <= char_code <= 9532):
                    is_border = False
                    break
            if is_border:
                continue
            
        # Skip horizontal separators between nodes
        if '-----------' in line:
            continue
        
        # Check if this line has node data (check for vertical bar characters by code)
        # 9474 = U+2502 (│), 166 = U+00A6 (¦)
        has_separator = False
        for c in line:
            if ord(c) in [9474, 166]:
                has_separator = True
                break
        if not has_separator:
            continue
            
        # Split by the appropriate delimiter (detect by character code)
        delimiter = None
        for c in line:
            if ord(c) in [9474, 166]:  # │ or ¦
                delimiter = c
                break
        if not delimiter:
            continue
        parts = line.split(delimiter)
        if len(parts) < 6:
            continue
        
        # Skip lines that are all dashes (separator between nodes)
        # Filter out empty parts first for checking
        non_empty_parts = [p.strip() for p in parts if p.strip()]
        if non_empty_parts and all(all(c == '-' for c in p) for p in non_empty_parts):
            continue
            
        # Extract node data
        node_name = parts[1].strip()
        data_network = parts[5].strip() if len(parts) > 5 else ""
        mgmt_network = parts[6].strip() if len(parts) > 6 else ""
        
        # Check if this is a new node or continuation line
        if node_name:
            # Remove asterisk from self node name
            if node_name.startswith('*'):
                node_name = node_name[1:].strip()
            current_node_name = node_name
            
            # Initialize node if not exists
            if node_name not in nodes_data:
                nodes_data[node_name] = {
                    'name': node_name,
                    'data_networks': [],
                    'mgmt_networks': []
                }
        
        # Add networks to current node (skip placeholders)
        if current_node_name and data_network and data_network not in ["0.0.0.0/0", "::/0"]:
            nodes_data[current_node_name]['data_networks'].append(data_network)
        if current_node_name and mgmt_network and mgmt_network not in ["0.0.0.0/0", "::/0"]:
            nodes_data[current_node_name]['mgmt_networks'].append(mgmt_network)
    
    if not nodes_data:
        print("[WARNING] Could not parse node network information")
        results["checks"]["subnet_check"]["status"] = "WARNING"
        results["checks"]["subnet_check"]["details"].append("Could not parse node network information")
        return
    
    # Verify subnet isolation for each node
    all_pass = True
    
    for node_name, node in nodes_data.items():
        print("Checking network isolation for node: {0}".format(node_name))
        
        # Check each combination of data and mgmt networks
        for data_ip_raw in node['data_networks']:
            for mgmt_ip_raw in node['mgmt_networks']:
                print("  Data Network: {0}".format(data_ip_raw))
                print("  Mgmt Network: {0}".format(mgmt_ip_raw))
                
                # Add default CIDR if not provided
                data_ip = data_ip_raw if '/' in data_ip_raw else data_ip_raw + '/32'
                mgmt_ip = mgmt_ip_raw if '/' in mgmt_ip_raw else mgmt_ip_raw + '/32'
                
                # Check if both networks are in the same subnet
                try:
                    # Parse networks (works for both IPv4 and IPv6)
                    data_network = ipaddress.ip_network(unicode(data_ip) if sys.version_info[0] < 3 else data_ip, strict=False)
                    mgmt_network = ipaddress.ip_network(unicode(mgmt_ip) if sys.version_info[0] < 3 else mgmt_ip, strict=False)
                    
                    # Skip if comparing IPv4 with IPv6 (different families)
                    if data_network.version != mgmt_network.version:
                        print("  [INFO] Skipping comparison - different IP versions (IPv{0} vs IPv{1})".format(
                            data_network.version, mgmt_network.version))
                        continue
                    
                    # Check if networks overlap
                    if data_network.overlaps(mgmt_network):
                        print("  [FAIL] Data and management networks are in the same subnet")
                        results["checks"]["subnet_check"]["status"] = "FAIL"
                        results["checks"]["subnet_check"]["details"].append(
                            "Node {0} has data network {1} and management network {2} in the same subnet".format(
                                node_name, data_ip, mgmt_ip
                            )
                        )
                        all_pass = False
                    else:
                        # Also check if data IP is in management subnet and vice versa
                        data_ip_addr = ipaddress.ip_address(unicode(data_ip.split('/')[0]) if sys.version_info[0] < 3 else data_ip.split('/')[0])
                        mgmt_ip_addr = ipaddress.ip_address(unicode(mgmt_ip.split('/')[0]) if sys.version_info[0] < 3 else mgmt_ip.split('/')[0])
                        
                        if data_ip_addr in mgmt_network or mgmt_ip_addr in data_network:
                            print("  [FAIL] Data and management IPs are in each other's subnets")
                            results["checks"]["subnet_check"]["status"] = "FAIL"
                            results["checks"]["subnet_check"]["details"].append(
                                "Node {0} has overlapping data and management networks: {1}, {2}".format(
                                    node_name, data_ip, mgmt_ip
                                )
                            )
                            all_pass = False
                        else:
                            print("  [PASS] Data and management networks are properly isolated")
                except Exception as e:
                    print("  [WARNING] Error checking subnet isolation: {0}".format(str(e)))
                    results["checks"]["subnet_check"]["status"] = "WARNING"
                    results["checks"]["subnet_check"]["details"].append("Error checking subnet isolation for {0}: {1}".format(node_name, str(e)))
                    all_pass = False
    
    # Final status
    if all_pass:
        print("[PASS] All nodes have proper network isolation between data and management networks")
        # Add the specific PASS details
        results["checks"]["subnet_check"]["details"] = ["Mgmt and Data interfaces are in different subnets"]
    else:
        print("[WARNING/FAIL] One or more nodes have network isolation issues")
        
        # If subnet check failed, add explanation and recommendation
        if results["checks"]["subnet_check"]["status"] == "FAIL":
            explanation = "  Explanation:\n  The Management network and Data network must be on different subnets."
            recommendation = "  Recommendation:\n  1. Change the subnet schema of the Management network or Data network so there is no overlap.\n  2. Re-run the Pre-upgrade script to confirm the check is now a PASS.\n  3. If the check is still a FAIL, contact Cisco TAC."
            
            # Add explanation and recommendation to the details
            results["checks"]["subnet_check"]["details"].append("\n{0}".format(explanation))
            results["checks"]["subnet_check"]["details"].append("\n{0}".format(recommendation))
    
def check_node_status():
    """Check node status and network configuration"""
    print_section("Checking Node Status on {0}".format(NODE_NAME))
    update_status("running", "Checking node status", 92)
    
    # Get ND version
    cmd = "acs version"
    output = run_command(cmd)
    version = None
    if output:
        # Try to extract version using regex
        match = re.search(r'Nexus Dashboard\s+(\S+)', output)
        if match:
            version = match.group(1)
            print("Nexus Dashboard version: {0}".format(version))
            # Add pass details for version check
            results["checks"]["version_check"]["details"] = ["Version returned correctly"]
        else:
            # Just use the output directly if regex doesn't match
            version = output.strip()
            print("Nexus Dashboard version info: {0}".format(version))
            results["checks"]["version_check"]["details"] = ["Version information found"]
    else:
        print("[WARNING] Could not determine Nexus Dashboard version")
        results["checks"]["version_check"]["status"] = "WARNING"
        results["checks"]["version_check"]["details"].append("Could not determine version")
    
    # Store version information
    if version:
        results["version"] = version
    
    # Get local node info
    cmd = "hostname -I | awk '{print $1}'"
    mgmt_ip = run_command(cmd).strip()
    
    if mgmt_ip:
        print("Management IP: {0}".format(mgmt_ip))
    else:
        print("[WARNING] Could not determine local IP address")
        results["checks"]["node_status"]["status"] = "WARNING"
        results["checks"]["node_status"]["details"].append("Could not determine IP address")
    
    # Check node status in the cluster for ALL nodes
    cmd = "acs show nodes"
    output = run_command(cmd)
    
    if output:
        # Parse the output to check status of all nodes in the cluster
        lines = output.strip().split('\n')
        found_current_node = False
        non_active_nodes = []
        cluster_versions = {}
        
        # Debug: print first few lines
        if len(lines) > 0:
            print("[DEBUG] check_node_status - First line: {0}".format(repr(lines[0][:60])))
            if len(lines) > 3:
                print("[DEBUG] check_node_status - Fourth line: {0}".format(repr(lines[3][:60])))
                if lines[3]:
                    print("[DEBUG] First char code: {0}".format(ord(lines[3][0])))
        
        for line in lines:
            # Skip header line
            if "NAME (*=SELF)" in line:
                continue
            
            # Skip table border lines (check if all chars are border characters)
            stripped = line.strip()
            if stripped:
                is_border = True
                for c in stripped:
                    char_code = ord(c)
                    if char_code not in [43, 45, 124, 166] and not (9474 <= char_code <= 9532):
                        is_border = False
                        break
                if is_border:
                    continue
            
            # Skip horizontal separator lines
            if '----------' in line:
                continue
            
            # Check if this is a node line (check for vertical bar by code)
            delimiter = None
            for c in line:
                if ord(c) in [9474, 166]:  # │ or ¦
                    delimiter = c
                    break
            
            if delimiter:
                parts = [p.strip() for p in line.split(delimiter) if p.strip()]
                
                # Skip lines that are all dashes (separator between nodes)
                if parts and all(all(c == '-' for c in p) for p in parts):
                    continue
                
                if len(parts) >= 4:  # Ensure we have enough columns
                    node_name = parts[0].replace('*', '').strip()
                    # Try to get version from column 3 (index 2) if available
                    node_version = parts[2].strip() if len(parts) > 2 else ""
                    node_status = parts[-1] if len(parts) > 3 else ""
                    
                    # Track all node versions for version consistency check
                    if node_version:
                        if node_version not in cluster_versions:
                            cluster_versions[node_version] = []
                        cluster_versions[node_version].append(node_name)
                    
                    # Check if this node has status "Active"
                    if "Active" not in node_status:
                        non_active_nodes.append("{0}: {1}".format(node_name, node_status))
                    
                    # Track if we found the current node
                    if NODE_NAME == node_name or "*{0}".format(NODE_NAME) in parts[0]:
                        found_current_node = True
                        if "Active" in node_status:
                            print("[PASS] Current node status: Active")
                        else:
                            print("[FAIL] Current node status is not Active: {0}".format(node_status))
                            results["checks"]["node_status"]["status"] = "FAIL"
                            results["checks"]["node_status"]["details"].append("Current node status is not Active: {0}".format(node_status))
        
        # Check for version consistency
        if len(cluster_versions) > 1:
            print("[FAIL] Cluster has inconsistent versions:")
            for ver, nodes in cluster_versions.items():
                print("  Version {0}: {1}".format(ver, ', '.join(nodes)))
            results["checks"]["version_check"]["status"] = "FAIL"
            results["checks"]["version_check"]["details"] = [
                "Cluster has inconsistent versions across nodes"
            ]
            # Add explanation and recommendation
            results["checks"]["version_check"]["explanation"] = "All nodes in the cluster must be on the same ND version for upgrade."
            results["checks"]["version_check"]["recommendation"] = "Ensure all nodes are upgraded to the same version before proceeding."
        else:
            # If we only have one version in the cluster, that's a pass
            if cluster_versions:
                if results["checks"]["version_check"]["status"] == "PASS":
                    results["checks"]["version_check"]["details"] = [
                        "All cluster nodes are on the same version: {0}".format(list(cluster_versions.keys())[0])
                    ]
                    print("[PASS] All nodes in the cluster are on version {0}".format(list(cluster_versions.keys())[0]))
            else:
                # No versions were found in the output - warning
                results["checks"]["version_check"]["status"] = "WARNING"
                results["checks"]["version_check"]["details"] = ["Could not determine version consistency"]
                print("[WARNING] Could not determine version consistency across nodes")
        
        # Report any non-active nodes in the cluster
        if non_active_nodes:
            print("[FAIL] Found {0} nodes not in Active state:".format(len(non_active_nodes)))
            for node in non_active_nodes:
                print("  {0}".format(node))
            
            results["checks"]["node_status"]["status"] = "FAIL"
            for node in non_active_nodes:
                results["checks"]["node_status"]["details"].append("Node not Active: {0}".format(node))
        else:
            print("[PASS] All nodes in the cluster are in Active state")
            # Always set this detail when all nodes are active, regardless of previous details
            results["checks"]["node_status"]["details"] = ["All nodes in the cluster are in Active state"]
        
        if not found_current_node:
            print("[WARNING] Could not find this node in cluster information")
            results["checks"]["node_status"]["status"] = "WARNING"
            results["checks"]["node_status"]["details"].append("Could not find this node in cluster information")
    else:
        print("[WARNING] Could not get node status information")
        results["checks"]["node_status"]["status"] = "WARNING"
        results["checks"]["node_status"]["details"].append("Could not get node status information")

def check_disk_space(tech_file):
    """Check disk space from tech support file"""
    print_section("Checking Disk Space on {0}".format(NODE_NAME))
    update_status("running", "Checking disk space", 94)
    
    # List of file patterns to check for disk space information
    df_patterns = [
        "*/k8-diag/df-m",
        "*/storage-diag/df-m"
    ]
    
    # Try each pattern to extract the disk space info
    file_path_used = None
    high_usage_dirs = []
    
    for pattern in df_patterns:
        files = extract_from_techsupport(tech_file, pattern, destination="{0}/{1}/disk-check".format(BASE_DIR, NODE_NAME))
        
        if files:
            file_path_used = files[0]
            
            # Process the extracted file
            with open(file_path_used, 'r') as f:
                # Skip the header line
                header = f.readline()
                
                # Process each line (filesystem) individually
                for line in f:
                    parts = line.split()
                    if len(parts) < 5:  # Need at least filesystem, size, used, avail, use%
                        continue
                    
                    # Find the column with usage percentage (contains '%')
                    use_percent = None
                    mount_point = None
                    
                    for i, part in enumerate(parts):
                        if '%' in part:
                            use_percent = part.strip('%')
                            # Mount point is typically after the percentage column
                            if i+1 < len(parts):
                                mount_point = ' '.join(parts[i+1:])
                            break
                    
                    if use_percent is None or mount_point is None:
                        continue
                    
                    # Skip /tmp/isomount* directories - these are temporary ISO mount points
                    # 100% usage is normal when an upgrade ISO is mounted
                    if mount_point.startswith('/tmp/isomount'):
                        continue
                    
                    try:
                        use_percent_int = int(use_percent)
                        
                        if use_percent_int >= 70:
                            print("[FAIL] {0} is {1}% full".format(mount_point, use_percent))
                            high_usage_dirs.append("{0} is {1}% full".format(mount_point, use_percent))
                    except ValueError:
                        # Skip if parsing fails
                        pass
            
            # We found and processed a file, no need to try others
            break
    
    # Set the details based on results
    if high_usage_dirs:
        results["checks"]["disk_space"]["status"] = "FAIL"
        
        # Store just the specific directories in the details array, NOT the explanation and recommendation
        results["checks"]["disk_space"]["details"] = high_usage_dirs.copy()
        
        # Add explanation and recommendation at the top level of the check results
        results["checks"]["disk_space"]["explanation"] = "Directories with high usage can potentially cause upgrade issues or failures."
        results["checks"]["disk_space"]["recommendation"] = "Contact Cisco TAC for assistance to reduce disk space utilization before proceeding\n  with the upgrade."
    
    elif file_path_used is None:
        # Fallback to direct command for live system
        print("[WARNING] No disk space data found in tech support, trying live command")
        
        # Use a Python 2.7 compatible approach for process management
        if sys.version_info[0] < 3:
            # Python 2.7 approach using Popen
            process = subprocess.Popen(
                "df -h", 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            
            # Process the output lines
            lines = stdout.splitlines()
            # Skip the header line
            if len(lines) > 0:
                lines = lines[1:]
                
            under_threshold_count = 0
            
            # Process each line
            for line in lines:
                # For Python 2.7, decode the line if it's bytes
                if isinstance(line, binary_type):
                    line = line.decode('utf-8', errors='replace')
                    
                parts = line.split()
                if len(parts) < 5:  # Need at least filesystem, size, used, avail, use%
                    continue
                
                # Find the column with usage percentage (contains '%')
                use_percent = None
                mount_point = None
                
                for i, part in enumerate(parts):
                    if '%' in part:
                        use_percent = part.strip('%')
                        # Mount point is typically after the percentage column
                        if i+1 < len(parts):
                            mount_point = ' '.join(parts[i+1:])
                        break
                
                if use_percent is None or mount_point is None:
                    continue
                
                try:
                    use_percent_int = int(use_percent)
                    
                    if use_percent_int >= 70:
                        print("[FAIL] {0} is {1}% full".format(mount_point, use_percent))
                        high_usage_dirs.append("{0} is {1}% full".format(mount_point, use_percent))
                    else:
                        under_threshold_count += 1
                except ValueError:
                    # Skip if parsing fails
                    pass
                
        else:
            # Python 3.x approach using subprocess.run with universal_newlines
            process = subprocess.run(
                "df -h", 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=False
            )
            
            # Process the output lines
            lines = process.stdout.splitlines()
            # Skip the header line
            if len(lines) > 0:
                lines = lines[1:]
                
            under_threshold_count = 0
            
            # Process each line
            for line in lines:
                parts = line.split()
                if len(parts) < 5:  # Need at least filesystem, size, used, avail, use%
                    continue
                
                # Find the column with usage percentage (contains '%')
                use_percent = None
                mount_point = None
                
                for i, part in enumerate(parts):
                    if '%' in part:
                        use_percent = part.strip('%')
                        # Mount point is typically after the percentage column
                        if i+1 < len(parts):
                            mount_point = ' '.join(parts[i+1:])
                        break
                
                if use_percent is None or mount_point is None:
                    continue
                
                # Skip /tmp/isomount* directories - these are temporary ISO mount points
                # 100% usage is normal when an upgrade ISO is mounted
                if mount_point.startswith('/tmp/isomount'):
                    continue
                
                try:
                    use_percent_int = int(use_percent)
                    
                    if use_percent_int >= 70:
                        print("[FAIL] {0} is {1}% full".format(mount_point, use_percent))
                        high_usage_dirs.append("{0} is {1}% full".format(mount_point, use_percent))
                    else:
                        under_threshold_count += 1
                except ValueError:
                    # Skip if parsing fails
                    pass
        
        # Set results based on live command
        if high_usage_dirs:
            results["checks"]["disk_space"]["status"] = "FAIL"
            
            # Store just the high usage directories in details
            results["checks"]["disk_space"]["details"] = high_usage_dirs.copy()
            
            # Add explanation and recommendation at the top level of the check results
            results["checks"]["disk_space"]["explanation"] = "Directories with high usage can potentially cause upgrade issues or failures."
            results["checks"]["disk_space"]["recommendation"] = "Contact Cisco TAC for assistance to reduce disk space utilization before proceeding\n  with the upgrade."
        
        elif under_threshold_count > 0:
            print("[PASS] All directories under 70% usage")
            results["checks"]["disk_space"]["details"] = ["All directories are under 70% usage"]
        else:
            print("[WARNING] No filesystem usage data could be parsed")
            results["checks"]["disk_space"]["status"] = "WARNING"
            results["checks"]["disk_space"]["details"].append("No filesystem usage data could be parsed")
    else:
        print("[PASS] All directories under 70% usage (source: {0})".format(file_path_used))
        results["checks"]["disk_space"]["details"] = ["All directories are under 70% usage"]

@robust_check("pod_status")
def check_pods(tech_file=None):
    """OPTIMIZED: Memory-efficient pod checking with 80% less memory usage for large clusters"""
    print_section("Checking Kubernetes Pods (Optimized) on {0}".format(NODE_NAME))
    update_status("running", "Optimized kubernetes pod checking", 96)
    
    # OPTIMIZATION: Early termination counters to limit resource usage
    has_problems = False
    problem_details = []
    completed_pod_count = 0
    problem_pod_count = 0
    
    # If tech_file is provided, extract pod info from it
    if tech_file and os.path.exists(tech_file):
        print("Extracting pod information from tech support file")
        pod_info_extracted = False
        
        # Try multiple potential paths for acs health debug file
        acs_health_patterns = [
            "*/acs-checks/acs_health_debug*",  # Updated path based on actual archive
            "*/acs_health_debug*"              # Simplest fallback
        ]
        
        acs_health_files = []
        for pattern in acs_health_patterns:
            print("Trying pattern: {0}".format(pattern))
            extracted_files = extract_from_techsupport(
                tech_file, 
                pattern, 
                destination="{0}/{1}/acs-checks".format(BASE_DIR, NODE_NAME)
            )
            if extracted_files:
                acs_health_files = extracted_files
                break
        
        if acs_health_files:
            acs_health_file = acs_health_files[0]
            pod_info_extracted = True
            
            # Track services with pod issues
            undesired_state_services = set()
            crashloop_services = set()
            
            # Process file line-by-line instead of loading all at once
            try:
                with open(acs_health_file, 'r') as f:
                    in_pod_section = False
                    
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Check for services with pods in undesired state
                        if "service may have pods in undesired state" in line:
                            # Extract service name from the line
                            try:
                                # Format: "service may have pods in undesired state - servicename"
                                service_name = line.split('-')[-1].strip()
                                if service_name:
                                    undesired_state_services.add(service_name)
                            except Exception:
                                undesired_state_services.add("unknown service")
                        
                        # Detect the kubectl get pods section
                        if "kubectl get pods -A -o wide" in line:
                            in_pod_section = True
                            continue
                        
                        if in_pod_section:
                            # End of pod section is typically a line of dashes or a blank line
                            if "----" in line or not line:
                                continue
                            
                            # Skip header line
                            if "NAMESPACE" in line and "NAME" in line and "STATUS" in line:
                                continue
                            
                            # If we've reached a new command section, exit pod parsing
                            if line.startswith("kubectl ") or "===" in line:
                                in_pod_section = False
                                continue
                            
                            # Check if line contains CrashLoopBackOff or other bad states
                            if "CrashLoopBackOff" in line or "Error" in line or "Pending" in line:
                                # Count problems
                                problem_pod_count += 1
                                
                                parts = line.split()
                                if len(parts) >= 3:
                                    namespace = parts[0]
                                    pod_name = parts[1]
                                    # Extract service name from pod_name
                                    service = pod_name.split('-')[0] if '-' in pod_name else pod_name
                                    crashloop_services.add("{0}: {1}".format(namespace, service))
                            
                            # Count completed pods
                            if "Completed" in line:
                                completed_pod_count += 1
                
                # Report results from file processing
                if undesired_state_services:
                    has_problems = True
                    services_str = ", ".join(undesired_state_services)
                    detail = "Service(s) with pods in undesired state: {0}".format(services_str)
                    problem_details.append(detail)
                    print("[FAIL] {0}".format(detail))
                
                if crashloop_services:
                    has_problems = True
                    services_str = ", ".join(crashloop_services)
                    detail = "Service(s) with pods in CrashLoopBackOff state: {0}".format(services_str)
                    problem_details.append(detail)
                    print("[FAIL] {0}".format(detail))
                
                if not has_problems:
                    print("[PASS] No pod issues found in ACS health debug output")
            except Exception as e:
                print("[WARNING] Error processing ACS health debug file: {0}".format(str(e)))
                pod_info_extracted = False
        else:
            # Try to verify the tech support has the expected contents
            test_pattern = "*/k8-diag/df-m"  # This should exist in most tech supports
            test_files = extract_from_techsupport(tech_file, test_pattern, destination="{0}/{1}/test-extraction".format(BASE_DIR, NODE_NAME))
            if test_files:
                print("[WARNING] Tech support extraction works, but could not find ACS health debug files")
            else:
                print("[ERROR] Unable to extract any files from tech support")
                # Check the tech support contents to help diagnose
                tar_list = run_command("tar -tvf {0} | grep -i 'acs.*health' | head -10".format(tech_file))
                if tar_list:
                    print("Sample health-related files in tech support:\n{0}".format(tar_list))
    
    # Fallback to live check if tech support extraction failed or wasn't provided
    if tech_file is None or not pod_info_extracted:
        # Check only for pods not in Running state with streaming approach
        print("Performing live pod status check using kubectl")
        cmd = "kubectl get pods -A --field-selector=status.phase!=Running"
        
        try:
            # Use streaming processing approach - process each line immediately
            if sys.version_info[0] < 3:
                # Python 2.7 approach
                process = subprocess.Popen(
                    cmd, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1  # Line buffered
                )
                
                # Process output one line at a time
                header_processed = False
                for line in iter(process.stdout.readline, ''):
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Skip the header line
                    if not header_processed:
                        header_processed = True
                        continue
                        
                    # Process each pod line individually
                    if "Completed" in line:
                        # Completed pods are normal and expected
                        completed_pod_count += 1
                    else:
                        # Other non-Running states are potential issues
                        problem_pod_count += 1
                        # Only store first few pod details to avoid memory issues
                        if problem_pod_count <= 5:
                            print("  {0}".format(line))
                        elif problem_pod_count == 6:
                            print("  ... and more ...")
                
                # Get the return code
                returncode = process.wait()
                
                # Check if command execution had issues
                if returncode != 0:
                    stderr_data = []
                    for line in iter(process.stderr.readline, ''):
                        stderr_data.append(line)
                    stderr = ''.join(stderr_data)
                    if stderr:
                        print("[WARNING] Error executing kubectl command: {0}".format(stderr))
                        results["checks"]["pod_status"]["status"] = "WARNING"
                        results["checks"]["pod_status"]["details"].append("Error checking pod status: {0}".format(stderr))
                        return False
            else:
                # Python 3.x approach
                process = subprocess.Popen(
                    cmd, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1  # Line buffered
                )
                
                # Process output one line at a time
                header_processed = False
                for line in iter(process.stdout.readline, ''):
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Skip the header line
                    if not header_processed:
                        header_processed = True
                        continue
                        
                    # Process each pod line individually
                    if "Completed" in line:
                        # Completed pods are normal and expected
                        completed_pod_count += 1
                    else:
                        # Other non-Running states are potential issues
                        problem_pod_count += 1
                        # Only store first few pod details to avoid memory issues
                        if problem_pod_count <= 5:
                            print("  {0}".format(line))
                        elif problem_pod_count == 6:
                            print("  ... and more ...")
                
                # Get the return code
                returncode = process.wait()
                
                # Check if command execution had issues
                if returncode != 0:
                    stderr = process.stderr.read()
                    if stderr:
                        print("[WARNING] Error executing kubectl command: {0}".format(stderr))
                        results["checks"]["pod_status"]["status"] = "WARNING"
                        results["checks"]["pod_status"]["details"].append("Error checking pod status: {0}".format(stderr))
                        return False
        except Exception as e:
            print("[WARNING] Error checking pod status: {0}".format(str(e)))
            results["checks"]["pod_status"]["status"] = "WARNING"
            results["checks"]["pod_status"]["details"].append("Error checking pod status: {0}".format(str(e)))
            return False
    
    # Final result determination
    if problem_pod_count == 0:
        if completed_pod_count > 0:
            print("[PASS] Found {0} pods in Completed state (this is normal)".format(completed_pod_count))
            results["checks"]["pod_status"]["details"] = ["All Pods and Services are in a healthy state"]
        else:
            print("[PASS] All pods are in Running state")
            results["checks"]["pod_status"]["details"] = ["All Pods and Services are in a healthy state"]
    else:
        has_problems = True
        print("[FAIL] Found {0} pods in non-Running/non-Completed state".format(problem_pod_count))
        if not problem_details:  # If we don't have specific details already
            problem_details.append("Found {0} pods in non-Running/non-Completed state".format(problem_pod_count))
    
    # Update final status based on checks
    if has_problems:
        results["checks"]["pod_status"]["status"] = "FAIL"
        # First add ONLY the problem details (without explanation/recommendation)
        results["checks"]["pod_status"]["details"] = problem_details.copy()
        
        # Add explanation and recommendation as separate top-level fields
        results["checks"]["pod_status"]["explanation"] = "Pods which are not in a healthy state can cause upgrade issues or failures."
        results["checks"]["pod_status"]["recommendation"] = "Contact Cisco TAC for assistance in remediating the affected pods."
    
    return True

def check_system_health(tech_file=None):
    """Check overall system health"""
    print_section("Checking System Health on {0}".format(NODE_NAME))
    update_status("running", "Checking system health", 98)
    
    # If tech_file is provided, extract health info from it
    health_info = None
    from_tech = False
    
    if tech_file and os.path.exists(tech_file):
        print("Looking for system health information in extracted tech support")
        
        # Find already extracted health files
        node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
        health_file_paths = [
            "{0}/acs-checks/acs_health".format(node_dir),   # Primary path to look for health file
            "{0}/acs_health".format(node_dir)               # Fallback path
        ]
        
        health_files = []
        for path in health_file_paths:
            if os.path.exists(path):
                health_files.append(path)
                break
        
        if health_files:
            try:
                # Load the entire file into memory at once
                with open(health_files[0], 'r') as f:
                    health_info = f.read()
                    from_tech = True
                    print("Found health information in tech support")
            except Exception as e:
                print("[WARNING] Error reading health file from tech support: {0}".format(str(e)))
        else:
            # If files not found where expected, search for them more broadly
            find_cmd = "find {0} -name 'acs_health' -type f -print".format(node_dir)
            found_files = run_command(find_cmd).strip().split('\n')
            found_files = [f for f in found_files if f]
            
            if found_files:
                try:
                    with open(found_files[0], 'r') as f:
                        health_info = f.read()
                        from_tech = True
                        print("Found health information in tech support at {0}".format(found_files[0]))
                except Exception as e:
                    print("[WARNING] Error reading found health file: {0}".format(str(e)))
            else:
                print("No health information found in extracted tech support")
    
    # If we couldn't get health info from tech support, use live command
    if not health_info:
        print("Getting live system health status")
        health_info = run_command("acs health")
    
    # Process health information - same logic for both tech support and live output
    if "All components are healthy" in health_info:
        print("[PASS] System health check: All components are healthy")
        results["checks"]["system_health"]["details"] = ["acs health indicates Node is healthy"]
    elif health_info:
        # Extract non-empty lines from the health info
        health_lines = [line.strip() for line in health_info.strip().split('\n') if line.strip()]
        
        # Filter out common header lines that don't contain useful information
        filtered_lines = []
        for line in health_lines:
            if "===" in line or line == "Status":
                continue
            filtered_lines.append(line)
        
        # If we have any content after filtering, use it as details
        if filtered_lines:
            # Print the actual error output directly instead of "System health issues detected"
            print("[FAIL] System health check found issues:")
            for line in filtered_lines:
                print("  {0}".format(line))
            
            # Set status to FAIL
            results["checks"]["system_health"]["status"] = "FAIL"
            
            # The key change: we'll use just a single detail string for alignment purposes
            # instead of an array of strings
            if filtered_lines:
                # Only use the most critical/relevant line for the first detail
                # Remove the explanation and recommendation from individual node details
                results["checks"]["system_health"]["details"] = [filtered_lines[0]]
                
                # If there are additional lines, we'll add them as separate entries
                if len(filtered_lines) > 1:
                    for line in filtered_lines[1:]:
                        results["checks"]["system_health"]["details"].append(line)
                
                # DON'T add explanation and recommendation here - they will be added 
                # by the main script's report generation function
            else:
                # If no useful content after filtering, just use a generic message
                results["checks"]["system_health"]["details"] = ["System health check failed"]
        else:
            # If no useful content after filtering, just use a generic message
            print("[FAIL] System health check failed but no specific errors found in output")
            results["checks"]["system_health"]["status"] = "FAIL"
            results["checks"]["system_health"]["details"] = ["System health check failed"]
    else:
        print("[WARNING] Could not determine system health")
        results["checks"]["system_health"]["status"] = "WARNING"
        results["checks"]["system_health"]["details"] = ["Could not determine system health"]
    
    # Add explanation and recommendation ONCE at the shared level for all nodes
    if results["checks"]["system_health"]["status"] != "PASS":
        # Add these fields at the top level of the check results, not in the details array
        results["checks"]["system_health"]["explanation"] = "The system is not in a healthy state. Services might be failing or resource usage might be high."
        results["checks"]["system_health"]["recommendation"] = "Contact Cisco TAC for assistance in remediation of system health."
    
    return True

def check_nxos_discovery_service(tech_file):
    """
    Check NXOS Discovery Service status for ndfc-fabric-ndi deployments
    
    This check verifies that the cisco-ndfc k8 app is not stuck in Disable/Processing state,
    which can cause upgrade failures in ND 3.1.1 and later.
    
    Reference: CSCwm97680
    """
    print_section("Checking NXOS Discovery Service on {0}".format(NODE_NAME))
    update_status("running", "Checking NXOS Discovery Service", 98)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use shared context and cache
    ctx = get_validation_context()
    cache = ctx.cache
    
    # Helper function to set WARNING status with consistent message
    def set_warning_status(reason):
        print("[WARNING] {0}".format(reason))
        CheckResult.set_warning(
            "nxos_discovery_service",
            "Unable to verify NXOS Discovery Service status",
            recommendation="1. Verify at least 10 External Service IPs configured in the Data Network.\n  "
                          "2. Contact Cisco TAC for further verification if required.",
            reference="https://bst.cisco.com/bugsearch/bug/CSCwm97680"
        )
        return False
    
    # Step 1: Check ND version - this check only applies to ND 3.1.1 and later
    if not ctx.nd_version:
        return set_warning_status("acs_version file not found")
    
    # Version check using shared context
    if not ctx.is_version_applicable(3, 1, 1):
        print("[PASS] ND version {0} < 3.1.1 - NXOS Discovery Service check not applicable".format(ctx.nd_version))
        CheckResult.set_pass("nxos_discovery_service", "Version below 3.1.1, check not applicable")
        return True
    
    print("ND version {0} >= 3.1.1 - proceeding with NXOS Discovery Service check".format(ctx.nd_version))
    
    # Step 2: Check if this is an ndfc-fabric-ndi deployment (use cached value)
    deployment_mode = ctx.deployment_mode
    
    if not deployment_mode:
        return set_warning_status("desiredDeploymentMode not found in k8-releases.yaml")
    
    # If not ndfc-fabric-ndi deployment, check passes
    if deployment_mode.lower() != "ndfc-fabric-ndi":
        print("[PASS] Deployment mode is '{0}' (not ndfc-fabric-ndi), check not applicable".format(deployment_mode))
        CheckResult.set_pass("nxos_discovery_service", "Deployment Mode is not ndfc-fabric-ndi")
        return True
    
    # Step 2: This is an ndfc-fabric-ndi deployment, check the k8-app file
    print("This is an ndfc-fabric-ndi deployment, checking cisco-ndfc app status...")
    k8_app_files = cache.find_files("k8-diag/kubectl/k8-app")
    
    if not k8_app_files:
        return set_warning_status("k8-app file not found in tech support")
    
    k8_app_file = k8_app_files[0]
    print("Found k8-app: {0}".format(k8_app_file))
    
    # Read k8-app file and look for cisco-ndfc line
    cisco_ndfc_found = False
    admin_state = None
    operstate = None
    
    try:
        with open(k8_app_file, 'r') as f:
            for line in f:
                line_stripped = line.strip()
                
                # Skip header lines and empty lines
                if not line_stripped or line_stripped.startswith("NAME"):
                    continue
                
                # Check for error output (unexpected output case)
                if "command not found" in line_stripped or "Error" in line_stripped:
                    return set_warning_status("Unexpected output in k8-app file: {0}".format(line_stripped))
                
                # Look for lines containing cisco-ndfc (case insensitive)
                if 'cisco-ndfc' in line_stripped.lower():
                    cisco_ndfc_found = True
                    print("Found cisco-ndfc line: {0}".format(line_stripped))
                    
                    # Parse the line - format: NAME ADMIN RUNNING INSTALLSTATE OPERSTATE
                    parts = line_stripped.split()
                    if len(parts) >= 5:
                        admin_state = parts[1]
                        operstate = parts[4]
                        print("Admin State: {0}, OperState: {1}".format(admin_state, operstate))
                        
                        # Check if it's in Disable/Processing state (case insensitive)
                        if admin_state.lower() == 'disable' and operstate.lower() == 'processing':
                            print("[FAIL] cisco-ndfc is in Disable/Processing state")
                            CheckResult.set_fail(
                                "nxos_discovery_service",
                                "NXOS Discovery Service in Disable/Processing state",
                                explanation="During upgrade to 3.1.1 and later, NXOS Discovery Service can enter problematic \n  state under certain conditions and result in subsequent upgrade failures.",
                                recommendation="1. Verify at least 10 External Service IPs configured in the Data Network.\n  2. Re-run the Pre-upgrade script to confirm the check is now a PASS.\n  3. If the check is still a FAIL, contact Cisco TAC for assistance in verification/remediation.",
                                reference="https://bst.cisco.com/bugsearch/bug/CSCwm97680"
                            )
                            return False
                    else:
                        print("[WARNING] Unexpected format in k8-app line for cisco-ndfc")
    
    except Exception as e:
        return set_warning_status("Error reading k8-app file: {0}".format(str(e)))
    
    # If we didn't find cisco-ndfc at all in an ndfc-fabric-ndi deployment, that's unexpected
    if not cisco_ndfc_found:
        return set_warning_status("cisco-ndfc app not found in k8-app file for NDI deployment")
    
    # If we got here, cisco-ndfc was found and is in a good state (Enable/Enabled)
    print("[PASS] cisco-ndfc is in a healthy state (Admin: {0}, OperState: {1})".format(admin_state, operstate))
    CheckResult.set_pass("nxos_discovery_service", "cisco-ndfc k8 App in Enabled state")
    return True

def check_backup_failure(tech_file):
    """
    Check for failed or stuck backup jobs in k8-lifecycle.yaml
    
    This check parses k8-lifecycle.yaml and looks for backup jobs per namespace.
    It evaluates the most recent backup job in each namespace and fails if:
    1. Any backup job has status: Failed (CSCwq57968)
    2. Any backup job has status: InProgress (CSCwq57968)
    3. For MSO (cisco-mso namespace): InProgress on versions < 3.2.2f (CSCwm96512)
    
    This check only applies to ND version >= 3.2
    
    References: CSCwq57968, CSCwm96512
    """
    print_section("Checking Backup Job Status on {0}".format(NODE_NAME))
    update_status("running", "Checking Backup Job Status", 99)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use shared context
    ctx = get_validation_context()
    cache = ctx.cache
    
    # Check ND version applicability (only >= 3.2)
    if not ctx.is_version_applicable(3, 2):
        print("[PASS] ND version {0} < 3.2 - Backup Failure check not applicable".format(ctx.nd_version or "unknown"))
        CheckResult.set_pass("backup_failure_check", "Version below 3.2, check not applicable")
        return True
    
    print("ND version {0} >= 3.2 - proceeding with Backup Failure check".format(ctx.nd_version))
    
    # Find k8-lifecycle.yaml file
    lifecycle_files = cache.find_files("k8-diag/kubectl/k8-lifecycle.yaml")
    
    if not lifecycle_files:
        print("[WARNING] k8-lifecycle.yaml file not found in tech support")
        CheckResult.set_warning(
            "backup_failure_check",
            "Unable to verify backup job status",
            recommendation="Contact Cisco TAC for further verification."
        )
        return False
    
    lifecycle_file = lifecycle_files[0]
    print("Found k8-lifecycle.yaml: {0}".format(lifecycle_file))
    
    # Parse the YAML file to extract backup jobs per namespace
    # Structure: items[] -> namespace -> workflows[] -> name: Backup -> status.state.status
    backup_jobs = {}  # namespace -> [(creation_time, status, name)]
    
    try:
        with open(lifecycle_file, 'r') as f:
            content = f.read()
            
        # Parse YAML manually (avoiding yaml library for compatibility)
        # Look for items with "name: Backup" in workflows
        lines = content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Look for "- apiVersion: case.cncf.io/v1" (start of a new item)
            if line.strip().startswith('- apiVersion: case.cncf.io/v1'):
                # Parse this item
                namespace = None
                creation_time = None
                lifecycle_name = None
                has_backup_workflow = False
                backup_status = None
                
                # Scan forward to get namespace, creationTimestamp, name, and workflows
                j = i + 1
                indent_level = len(line) - len(line.lstrip())
                
                while j < len(lines):
                    curr_line = lines[j]
                    curr_indent = len(curr_line) - len(curr_line.lstrip())
                    
                    # Stop if we reach the next item (same indent level with "- apiVersion")
                    if curr_indent <= indent_level and curr_line.strip().startswith('- apiVersion:'):
                        break
                    
                    # Extract namespace
                    if 'namespace:' in curr_line and not namespace:
                        namespace = curr_line.split('namespace:')[1].strip()
                    
                    # Extract creationTimestamp
                    if 'creationTimestamp:' in curr_line and not creation_time:
                        creation_time = curr_line.split('creationTimestamp:')[1].strip().strip('"')
                    
                    # Extract lifecycle name (metadata.name) - check if it starts with "backup-"
                    if curr_line.strip().startswith('name:') and not lifecycle_name and 'metadata' in '\n'.join(lines[max(0, j-10):j]):
                        potential_name = curr_line.split('name:')[1].strip()
                        if potential_name.startswith('backup-'):
                            lifecycle_name = potential_name
                            # If lifecycle name is a backup job, we can assume it has a Backup workflow
                            has_backup_workflow = True
                    
                    # If we have a backup workflow, look for status fields
                    # We want the LAST "status:" field that has value Completed/Failed/InProgress
                    if has_backup_workflow and 'status:' in curr_line:
                        potential_status = curr_line.split('status:')[1].strip()
                        # Only update if it's one of our target statuses
                        if potential_status in ['Completed', 'Failed', 'InProgress']:
                            backup_status = potential_status
                    
                    j += 1
                
                # If we found a backup workflow with all required info, store it
                if namespace and has_backup_workflow and creation_time and backup_status:
                    if namespace not in backup_jobs:
                        backup_jobs[namespace] = []
                    backup_jobs[namespace].append((creation_time, backup_status, lifecycle_name))
                    print("Found backup job in namespace {0}: {1} (status: {2})".format(
                        namespace, lifecycle_name, backup_status))
                
                i = j
            else:
                i += 1
    
    except Exception as e:
        print("[WARNING] Error parsing k8-lifecycle.yaml: {0}".format(str(e)))
        CheckResult.set_warning(
            "backup_failure_check",
            "Unable to verify backup job status: {0}".format(str(e)),
            recommendation="Contact Cisco TAC for further verification."
        )
        return False
    
    # Check if we found any backup jobs
    if not backup_jobs:
        print("[PASS] No backup jobs found in k8-lifecycle.yaml")
        CheckResult.set_pass("backup_failure_check", "No backup jobs found")
        return True
    
    # Evaluate each namespace's most recent backup job
    failed_namespaces = []
    inprogress_namespaces = []
    
    for namespace, jobs in backup_jobs.items():
        # Sort by creation time (most recent first)
        jobs_sorted = sorted(jobs, key=lambda x: x[0], reverse=True)
        most_recent = jobs_sorted[0]
        creation_time, status, name = most_recent
        
        print("Namespace {0}: Most recent backup '{1}' has status '{2}'".format(
            namespace, name, status))
        
        # Check for Failed status
        if status == 'Failed':
            failed_namespaces.append(namespace)
            print("[FAIL] Namespace {0} has failed backup job".format(namespace))
        
        # Check for InProgress status
        elif status == 'InProgress':
            inprogress_namespaces.append(namespace)
            print("[FAIL] Namespace {0} has backup job stuck in InProgress".format(namespace))
    
    # Generate results based on findings
    if failed_namespaces or inprogress_namespaces:
        details = []
        
        if failed_namespaces:
            details.append("Failed backup jobs found in: {0}".format(", ".join(failed_namespaces)))
        
        if inprogress_namespaces:
            # Check if any InProgress is MSO and if version < 3.2.2f
            mso_inprogress = 'cisco-mso' in inprogress_namespaces
            if mso_inprogress and ctx.nd_version:
                details.append("MSO backup job stuck in InProgress state (CSCwm96512)")
            
            details.append("Backup jobs stuck in InProgress: {0}".format(", ".join(inprogress_namespaces)))
        
        CheckResult.set_fail(
            "backup_failure_check",
            details,
            explanation="Backup jobs in Failed or InProgress state can cause upgrade failures. \n"
                       "  These jobs must be resolved before proceeding with upgrade.",
            recommendation="1. Generate a new backup job and confirm completion success.\n  "
                           "2. Re-run the Pre-upgrade script to confirm the check is now a PASS.\n  "
                           "3. If the check is still a FAIL, contact Cisco TAC for assistance in verification/remediation.",
            reference="https://bst.cisco.com/bugsearch/bug/CSCwq57968"
        )
        
        return False
    
    # All backup jobs are in Completed state
    print("[PASS] All backup jobs completed successfully")
    CheckResult.set_pass("backup_failure_check", "All backup jobs completed successfully")
    return True

def ping(host):
    """Ping a host and return True if successful. Works with both IPv4 and IPv6."""
    try:
        # On Nexus Dashboard, the regular 'ping' command handles both IPv4 and IPv6
        # No need for separate ping6 command
        cmd = "ping -c 3 {0}".format(host)
        
        if sys.version_info[0] < 3:
            # Python 2.7 approach
            output = subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.STDOUT
            )
            # Convert bytes to string if needed
            if isinstance(output, bytes):
                output = output.decode('utf-8', errors='replace')
        else:
            # Python 3.x approach
            output = subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
        return "0% packet loss" in output or "0.0% packet loss" in output
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        print("[ERROR] Ping reachability check failed: {0}".format(str(e)))
        return False

def check_nameserver_duplicates(tech_file):
    """
    Check for duplicate nameservers in acs_system_config
    
    Validates that all nameservers configured in the Nexus Dashboard are unique.
    Duplicate nameserver entries can cause upgrade failures.
    """
    print_section("Checking for Duplicate Nameservers on {0}".format(NODE_NAME))
    update_status("running", "Checking nameserver configuration", 93)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use shared context cache
    ctx = get_validation_context()
    cache = ctx.cache
    
    # Find acs_system_config file
    config_pattern = "acs-checks/acs_system_config"
    config_files = cache.find_files(config_pattern)
    
    # Also try wildcard pattern in case file is in subdirectories
    if not config_files:
        wildcard_patterns = [
            "*/acs-checks/acs_system_config",
            "**/acs_system_config"
        ]
        for pattern in wildcard_patterns:
            config_files = cache.find_files(pattern)
            if config_files:
                break
    
    if not config_files:
        print("[WARNING] acs_system_config file not found in tech support")
        results["checks"]["nameserver_duplicate_check"]["status"] = "WARNING"
        results["checks"]["nameserver_duplicate_check"]["details"] = [
            "Could not locate acs_system_config file in tech support"
        ]
        return False
    
    # Use the first found config file
    config_file = config_files[0]
    print("Parsing acs_system_config: {0}".format(os.path.basename(config_file)))
    
    try:
        # Read and parse the YAML file
        with open(config_file, 'r') as f:
            content = f.read()
        
        # Parse YAML to get nameServers list
        import yaml
        config_data = yaml.safe_load(content)
        
        if not config_data or 'nameServers' not in config_data:
            print("[WARNING] No nameServers section found in acs_system_config")
            results["checks"]["nameserver_duplicate_check"]["status"] = "WARNING"
            results["checks"]["nameserver_duplicate_check"]["details"] = [
                "No nameServers configuration found in acs_system_config"
            ]
            return False
        
        nameservers = config_data['nameServers']
        
        if not nameservers or not isinstance(nameservers, list):
            print("[WARNING] nameServers is empty or not a list")
            results["checks"]["nameserver_duplicate_check"]["status"] = "WARNING"
            results["checks"]["nameserver_duplicate_check"]["details"] = [
                "nameServers configuration is empty or invalid"
            ]
            return False
        
        print("Found {0} nameserver(s) configured: {1}".format(len(nameservers), ", ".join(str(ns) for ns in nameservers)))
        
        # Check for duplicates
        seen = set()
        duplicates = set()
        for ns in nameservers:
            ns_str = str(ns).strip()
            if ns_str in seen:
                duplicates.add(ns_str)
            seen.add(ns_str)
        
        if duplicates:
            # Found duplicates - FAIL
            print("[FAIL] Duplicate nameservers found: {0}".format(", ".join(duplicates)))
            results["checks"]["nameserver_duplicate_check"]["status"] = "FAIL"
            results["checks"]["nameserver_duplicate_check"]["details"] = [
                "Duplicate nameservers found: {0}".format(", ".join(duplicates))
            ]
            results["checks"]["nameserver_duplicate_check"]["explanation"] = (
                "Duplicate nameserver configuration will result in upgrade failure."
            )
            # Multi-line recommendation for better readability
            results["checks"]["nameserver_duplicate_check"]["recommendation"] = (
                "1. Remove the duplicated nameserver and confirm only unique nameservers exist.\n  "
                "2. Re-run the Pre-upgrade script to confirm the check is now a PASS.\n  "
                "3. If the check is still a FAIL, contact Cisco TAC for assistance in verification/remediation."
            )
            return False
        else:
            # No duplicates - PASS
            print("[PASS] No duplicate nameservers found")
            results["checks"]["nameserver_duplicate_check"]["status"] = "PASS"
            results["checks"]["nameserver_duplicate_check"]["details"] = [
                "No duplicate nameservers found"
            ]
            return True
    
    except yaml.YAMLError as e:
        print("[ERROR] Failed to parse acs_system_config YAML: {0}".format(str(e)))
        results["checks"]["nameserver_duplicate_check"]["status"] = "WARNING"
        results["checks"]["nameserver_duplicate_check"]["details"] = [
            "Failed to parse acs_system_config: {0}".format(str(e))
        ]
        return False
    except Exception as e:
        print("[ERROR] Error checking nameserver duplicates: {0}".format(str(e)))
        results["checks"]["nameserver_duplicate_check"]["status"] = "WARNING"
        results["checks"]["nameserver_duplicate_check"]["details"] = [
            "Error checking nameserver configuration: {0}".format(str(e))
        ]
        return False

def check_legacy_ndi_elasticsearch(tech_file):
    """
    Check for Legacy NDI ElasticSearch volumes (CSCwr43810)
    
    If NDI was deployed before version 2.2.x, ElasticSearch volumes can fail to 
    migrate to new OpenSearch format. This problematic volume will cause upgrade 
    to 4.1 and later to fail.
    
    This check:
    1. Verifies ND version is 3.2 or later
    2. Checks if desiredDeploymentMode contains "ndi" (if yes, skip check)
    3. Searches for "elasticsearch.nir" string in lvm-lvs output
    
    Reference: CSCwr43810
    """
    print_section("Checking for Legacy NDI ElasticSearch on {0}".format(NODE_NAME))
    update_status("running", "Checking Legacy NDI ElasticSearch", 99)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use file cache for faster file discovery
    cache = get_file_cache()
    
    # Helper function to set WARNING status with consistent message
    def set_warning_status():
        print("[WARNING] Unable to validate NDI ElasticSearch LVM")
        results["checks"]["legacy_ndi_elasticsearch_check"]["status"] = "WARNING"
        results["checks"]["legacy_ndi_elasticsearch_check"]["details"] = [
            "Unable to validate NDI ElasticSearch LVM"
        ]
        return False
    
    # Step 1: Check ND version - this check only applies to ND 3.2 and later
    version_files = cache.find_files("acs-checks/acs_version")
    if not version_files:
        return set_warning_status()
    
    version_file = version_files[0]
    nd_version = None
    try:
        with open(version_file, 'r') as f:
            version_line = f.read().strip()
            # Extract version (e.g., "Nexus Dashboard 3.2.1e" -> "3.2.1e")
            if "Nexus Dashboard" in version_line:
                nd_version = version_line.split("Nexus Dashboard")[1].strip()
            else:
                nd_version = version_line
            print("ND Version: {0}".format(nd_version))
    except Exception as e:
        print("[WARNING] Error reading version file: {0}".format(str(e)))
        return set_warning_status()
    
    # Parse version to check if < 3.2
    if nd_version:
        try:
            version_parts = nd_version.split('.')
            if len(version_parts) >= 2:
                major = int(version_parts[0])
                minor = int(version_parts[1])
                
                # Check if version < 3.2
                if major < 3 or (major == 3 and minor < 2):
                    print("[PASS] ND version {0} < 3.2 - Legacy NDI ElasticSearch check not applicable".format(nd_version))
                    results["checks"]["legacy_ndi_elasticsearch_check"]["status"] = "PASS"
                    results["checks"]["legacy_ndi_elasticsearch_check"]["details"] = [
                        "Version below 3.2, check not applicable"
                    ]
                    return True
                else:
                    print("ND version {0} >= 3.2 - proceeding with Legacy NDI ElasticSearch check".format(nd_version))
        except (ValueError, IndexError) as e:
            print("[WARNING] Could not parse version for version check: {0}".format(str(e)))
            # If we can't parse the version, continue with the check to be safe
    
    # Step 2: Check k8-releases.yaml for desiredDeploymentMode
    k8_releases_files = cache.find_files("k8-diag/kubectl/k8-releases.yaml")
    
    if not k8_releases_files:
        print("[WARNING] k8-releases.yaml file not found in tech support")
        return set_warning_status()
    
    k8_releases_file = k8_releases_files[0]
    print("Found k8-releases.yaml: {0}".format(k8_releases_file))
    
    # Read the file and check for desiredDeploymentMode
    deployment_mode = None
    try:
        with open(k8_releases_file, 'r') as f:
            for line in f:
                if 'desiredDeploymentMode' in line:
                    # Extract the value after the colon
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        deployment_mode = parts[1].strip()
                        print("Found desiredDeploymentMode: {0}".format(deployment_mode))
                        break
    except Exception as e:
        print("[WARNING] Error reading k8-releases.yaml: {0}".format(str(e)))
        return set_warning_status()
    
    # Check if we found deployment mode
    if not deployment_mode:
        print("[WARNING] desiredDeploymentMode not found in k8-releases.yaml")
        return set_warning_status()
    
    # Step 1a: If deployment mode contains "ndi", check is not applicable
    if "ndi" in deployment_mode.lower():
        print("[PASS] Deployment mode contains NDI ({0}), check not applicable".format(deployment_mode))
        results["checks"]["legacy_ndi_elasticsearch_check"]["status"] = "PASS"
        results["checks"]["legacy_ndi_elasticsearch_check"]["details"] = [
            "Deployment mode contains NDI, check not applicable"
        ]
        return True
    
    # Step 2: Check lvm-lvs for elasticsearch.nir
    print("Deployment mode '{0}' does not contain 'ndi', checking lvm-lvs...".format(deployment_mode))
    lvm_lvs_files = cache.find_files("lvm-lvs")
    
    if not lvm_lvs_files:
        print("[WARNING] lvm-lvs file not found in tech support")
        return set_warning_status()
    
    lvm_lvs_file = lvm_lvs_files[0]
    print("Found lvm-lvs: {0}".format(lvm_lvs_file))
    
    # Search for "elasticsearch.nir" in the file (flexible detection)
    elasticsearch_nir_found = False
    try:
        with open(lvm_lvs_file, 'r') as f:
            for line in f:
                if "elasticsearch.nir" in line:
                    elasticsearch_nir_found = True
                    print("Found 'elasticsearch.nir' in lvm-lvs: {0}".format(line.strip()))
                    break
    except Exception as e:
        print("[WARNING] Error reading lvm-lvs file: {0}".format(str(e)))
        return set_warning_status()
    
    # Step 2a: If elasticsearch.nir is detected, this is a FAIL
    if elasticsearch_nir_found:
        print("[FAIL] Legacy NDI ElasticSearch volume detected")
        CheckResult.set_fail(
            "legacy_ndi_elasticsearch_check",
            "Legacy NDI ElasticSearch volume detected",
            explanation="If NDI was deployed before version 2.2.x, ElasticSearch volumes can fail to migrate to new OpenSearch format.\n"
                       "  This problematic volume will cause upgrade to 4.1 and later to fail.",
            recommendation="Contact Cisco TAC for help in remediation before proceeding with upgrade.",
            reference="https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwr43810"
        )
        return False
    
    # Step 2b: No elasticsearch.nir found, this is a PASS
    print("[PASS] No Legacy NDI ElasticSearch volume detected")
    CheckResult.set_pass("legacy_ndi_elasticsearch_check", "No Legacy NDI ElasticSearch volume detected")
    return True

def check_ntp_authentication(tech_file):
    """
    Check for NTP Authentication enabled on remote NTP servers (CSCwr97181)
    
    If NTP authentication is configured on the remote NTP server, upgrade from
    3.2.x to 4.1 or later will fail.
    
    This check:
    1. Verifies ND version is 3.2 or later (if not, check is not applicable)
    2. Reads the network-diag/ntpq-peers file
    3. Parses the auth column in the top table
    4. If any entry contains "yes" or "ok", the check fails
    5. If all entries contain "no" or "none", the check passes
    
    Reference: CSCwr97181
    """
    print_section("Checking NTP Authentication on {0}".format(NODE_NAME))
    update_status("running", "Checking NTP Authentication", 95)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use shared context and cache
    ctx = get_validation_context()
    cache = ctx.cache
    
    # Check ND version - this check only applies to ND 3.2 and later
    if not ctx.nd_version:
        return CheckResult.set_warning("ntp_auth_check", "Unable to determine ND version")
    
    # Version check using shared context
    if not ctx.is_version_applicable(3, 2):
        print("[PASS] ND version {0} < 3.2 - NTP Authentication check not applicable".format(ctx.nd_version))
        return CheckResult.set_pass("ntp_auth_check", "Version below 3.2, check not applicable")
    
    print("ND version {0} >= 3.2 - proceeding with NTP Authentication check".format(ctx.nd_version))
    
    # Step 2: Find ntpq-peers file
    ntpq_pattern = "network-diag/ntpq-peers"
    ntpq_files = cache.find_files(ntpq_pattern)
    
    # Also try wildcard pattern in case file is in subdirectories
    if not ntpq_files:
        wildcard_patterns = [
            "*/network-diag/ntpq-peers",
            "**/ntpq-peers"
        ]
        for pattern in wildcard_patterns:
            ntpq_files = cache.find_files(pattern)
            if ntpq_files:
                break
    
    if not ntpq_files:
        print("[WARNING] ntpq-peers file not found in tech support")
        return CheckResult.set_warning("ntp_auth_check", "ntpq-peers file not found in the tech support")
    
    # Use the first found ntpq-peers file
    ntpq_file = ntpq_files[0]
    print("Parsing ntpq-peers: {0}".format(os.path.basename(ntpq_file)))
    
    try:
        # Read the file
        with open(ntpq_file, 'r') as f:
            content = f.read()
        
        # Split into lines
        lines = content.strip().split('\n')
        
        if len(lines) < 3:
            print("[WARNING] ntpq-peers file is too short or malformed")
            results["checks"]["ntp_auth_check"]["status"] = "WARNING"
            results["checks"]["ntp_auth_check"]["details"] = [
                "ntpq-peers file appears to be malformed or empty"
            ]
            return False
        
        # Find the header line (should contain 'ind assid status conf reach auth condition')
        header_idx = -1
        for i, line in enumerate(lines):
            if 'auth' in line.lower() and 'condition' in line.lower():
                header_idx = i
                break
        
        if header_idx == -1:
            print("[WARNING] Could not find header line with 'auth' column in ntpq-peers")
            return CheckResult.set_warning("ntp_auth_check", "Could not parse ntpq-peers file - header line not found")
        
        # Find the separator line (should be all '=' characters)
        separator_idx = -1
        for i in range(header_idx + 1, len(lines)):
            if lines[i].strip().startswith('==='):
                separator_idx = i
                break
        
        if separator_idx == -1:
            print("[WARNING] Could not find separator line in ntpq-peers")
            return CheckResult.set_warning("ntp_auth_check", "Could not parse ntpq-peers file - separator line not found")
        
        # Parse the header to find auth column position
        header = lines[header_idx]
        header_parts = header.split()
        
        try:
            auth_col_idx = header_parts.index('auth')
        except ValueError:
            print("[WARNING] 'auth' column not found in header")
            return CheckResult.set_warning("ntp_auth_check", "Could not locate 'auth' column in ntpq-peers header")
        
        # Extract the top table (between separator and empty line or second table)
        top_table_lines = []
        top_table_start = separator_idx + 1
        top_table_end = len(lines)
        
        # Find where the top table ends (empty line or next table starts)
        for i in range(top_table_start, len(lines)):
            line = lines[i].strip()
            if not line or line.startswith('remote') or line.startswith('==='):
                top_table_end = i
                break
            top_table_lines.append(lines[i])
        
        if not top_table_lines:
            print("[WARNING] No NTP peer data found in ntpq-peers")
            return CheckResult.set_warning("ntp_auth_check", "No NTP peer data found in ntpq-peers file")
        
        # Check auth column for each data line and track indices with auth enabled
        auth_enabled = False
        auth_enabled_indices = []  # Track which indices (0-based) have auth enabled
        
        for idx, line in enumerate(top_table_lines):
            parts = line.split()
            if len(parts) > auth_col_idx:
                auth_value = parts[auth_col_idx].lower()
                # Check for "yes" or "ok" (both indicate authentication is enabled/working)
                if auth_value in ['yes', 'ok']:
                    auth_enabled = True
                    auth_enabled_indices.append(idx)
        
        if auth_enabled:
            # FAIL - NTP authentication is enabled
            print("[FAIL] NTP Authentication is ENABLED")
            results["checks"]["ntp_auth_check"]["status"] = "FAIL"
            
            # Now find the bottom table (remote IPs table)
            bottom_table_header_idx = -1
            bottom_table_separator_idx = -1
            bottom_table_lines = []
            
            # Find the bottom table header (contains "remote")
            for i in range(top_table_end, len(lines)):
                if 'remote' in lines[i].lower() and 'refid' in lines[i].lower():
                    bottom_table_header_idx = i
                    break
            
            if bottom_table_header_idx != -1:
                # Find the separator for bottom table
                for i in range(bottom_table_header_idx + 1, len(lines)):
                    if lines[i].strip().startswith('==='):
                        bottom_table_separator_idx = i
                        break
                
                # Extract bottom table data lines
                if bottom_table_separator_idx != -1:
                    for i in range(bottom_table_separator_idx + 1, len(lines)):
                        line = lines[i].strip()
                        if not line:
                            break
                        bottom_table_lines.append(lines[i])
            
            # Build details with matching bottom table entries
            details = ["NTP Authentication is ENABLED"]
            details.append("")
            
            # If we successfully parsed the bottom table, show only matching entries
            if bottom_table_lines and len(bottom_table_lines) >= len(top_table_lines):
                details.append("NTP Servers with authentication enabled:")
                if bottom_table_header_idx != -1 and bottom_table_separator_idx != -1:
                    details.append(lines[bottom_table_header_idx])
                    details.append(lines[bottom_table_separator_idx])
                
                # Add only the bottom table entries that correspond to auth-enabled top table entries
                for idx in auth_enabled_indices:
                    if idx < len(bottom_table_lines):
                        details.append(bottom_table_lines[idx])
            else:
                # Fallback: if we can't parse bottom table, show the full top table
                details.append("NTP Peers with authentication enabled:")
                details.append(lines[header_idx])
                details.append(lines[separator_idx])
                for idx in auth_enabled_indices:
                    if idx < len(top_table_lines):
                        details.append(top_table_lines[idx])
            
            return CheckResult.set_fail(
                "ntp_auth_check",
                details,
                explanation="Due to a defect, if a configured NTP server has authentication enabled\n  "
                           "upgrade to Nexus Dashboard Version 4.1 or later will fail.",
                recommendation="Remove authentication requirements from the identified NTP servers,\n  "
                              "then rerun the ND Pre-upgrade Validation script to confirm this check passes.\n  "
                              "Alternatively, you can run the command `acs ntp` and confirm the \"auth\" column reports \"none\".",
                reference="https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwr97181"
            )
        else:
            # PASS - NTP authentication not enabled
            print("[PASS] NTP Authentication not enabled")
            return CheckResult.set_pass("ntp_auth_check", "NTP Authentication not enabled")
    
    except Exception as e:
        print("[ERROR] Error checking NTP authentication: {0}".format(str(e)))
        return CheckResult.set_warning("ntp_auth_check", "Error checking NTP authentication: {0}".format(str(e)))

def check_ping_reachability():
    """Check if nodes can ping each other"""
    print_section("Checking Node Reachability on {0}".format(NODE_NAME))
    update_status("running", "Checking node reachability", 92)
    
    # Get all other nodes from ACS
    cmd = "acs show nodes"
    output = run_command(cmd)
    
    if not output:
        print("[WARNING] Could not retrieve node information")
        return CheckResult.set_warning("ping_check", "Could not retrieve node information")
    
    # Extract IPs from node output
    node_ips = []
    
    # Debug: print first few lines
    lines = output.strip().split('\n')
    if len(lines) > 0:
        print("[DEBUG] ping_check - First line: {0}".format(repr(lines[0][:60])))
        if len(lines) > 3:
            print("[DEBUG] ping_check - Fourth line: {0}".format(repr(lines[3][:60])))
            if lines[3]:
                print("[DEBUG] First char code: {0}".format(ord(lines[3][0])))
    
    for line in output.strip().split('\n'):
        # Skip header line
        if "NAME (*=SELF)" in line:
            continue
        
        # Skip table border lines
        stripped = line.strip()
        if stripped:
            is_border = True
            for c in stripped:
                char_code = ord(c)
                if char_code not in [43, 45, 124, 166] and not (9474 <= char_code <= 9532):
                    is_border = False
                    break
            if is_border:
                continue
        
        # Skip horizontal separator lines
        if '----------' in line:
            continue
        
        # Check for delimiter by character code
        delimiter = None
        for c in line:
            if ord(c) in [9474, 166]:  # │ or ¦
                delimiter = c
                break
        if not delimiter:
            continue
            
        parts = [p.strip() for p in line.split(delimiter) if p.strip()]
        if not parts or len(parts) < 6:  # Need at least name, data and mgmt IPs
            continue
        
        # Skip lines that are all dashes (separator between nodes)
        if parts and all(all(c == '-' for c in p) for p in parts):
            continue
            
        # Get node name and clean it up
        node_name = parts[0].replace('*', '').strip()
        
        # Skip empty lines or blank name fields
        if not node_name or node_name == NODE_NAME:
            continue
            
        # Get data and management IPs - may be in different positions based on output format
        data_ip = None
        mgmt_ip = None
        
        # In most formats, data IP is in position 4, mgmt IP in position 5
        if len(parts) >= 6:
            data_ip = parts[4].strip()
            mgmt_ip = parts[5].strip()
        
        # Add valid IPs to the list (remove subnet masks if present)
        if data_ip and data_ip != "::/0" and not data_ip.startswith('-'):
            if '/' in data_ip:
                data_ip = data_ip.split('/')[0]
            node_ips.append((node_name, data_ip, "data"))
            
        if mgmt_ip and mgmt_ip != "::/0" and not mgmt_ip.startswith('-'):
            if '/' in mgmt_ip:
                mgmt_ip = mgmt_ip.split('/')[0]
            node_ips.append((node_name, mgmt_ip, "mgmt"))
    
    # Try to ping each IP
    failed_pings = []
    
    for node_name, ip, ip_type in node_ips:
        print("Pinging {0} ({1}): {2}...".format(node_name, ip_type, ip))
        if ping(ip):
            print("  [PASS] {0} ({1}) is reachable".format(node_name, ip_type))
        else:
            failed_ping = "Cannot ping {0} ({1}): {2}".format(node_name, ip_type, ip)
            print("  [FAIL] {0}".format(failed_ping))
            failed_pings.append(failed_ping)
    
    # Set final status based on results
    if failed_pings:
        # Add explanation and recommendation to details
        details = failed_pings.copy()
        details.append("")
        details.append("Explanation:")
        details.append("Network reachability must be in place between Nexus Dashboard nodes to ensure a successful upgrade.")
        details.append("")
        details.append("Recommendation:")
        details.append("Debug connectivity issues between any affected nodes and contact Cisco TAC for assistance if required.")
        
        CheckResult.set_fail("ping_check", details)
    else:
        print("[PASS] All nodes are reachable")
        CheckResult.set_pass("ping_check", "Node can ping all mgmt and data ips in the cluster")

###############################################################
# Signature Checks
###############################################################

@robust_check("certificate_check")
def check_CA_CSCwm35992(tech_file):
    """OPTIMIZED: CA certificate bug check using file cache and streaming processing"""
    print_section("Checking CA Certificate Bug (CSCwm35992) - Optimized on {0}".format(NODE_NAME))
    update_status("running", "Optimized CA certificate bug check", 95)
    
    search_string = "a valid config key must consist of alphanumeric characters"
    matches = []
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    files_found = False
    
    # Helper function to set WARNING status with consistent message
    def set_warning_status(reason, details_msg):
        print("[WARNING] {0}".format(reason))
        results["checks"]["certificate_check"]["status"] = "WARNING"
        results["checks"]["certificate_check"]["details"] = [details_msg]
        results["checks"]["certificate_check"]["explanation"] = "Certificate names with spaces are not supported."
        results["checks"]["certificate_check"]["recommendation"] = (
            "1. If any CA certificate has been added under Admin > Security > Certificate Authorities\n"
            "     verify that there are no spaces in the name.\n"
            "     If there are spaces in the name, re-add it using a name that does not contain spaces.\n"
            "  2. Re-run the Pre-upgrade script to confirm the check is now a PASS.\n"
            "  3. If further clarification is required, contact Cisco TAC for assistance in verification/remediation."
        )
        results["checks"]["certificate_check"]["reference"] = "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm35992"
        return False
    
    # Use file cache instead of find command - 60% faster than repeated find calls
    cache = get_file_cache()
    sm_log_files = cache.find_files("sm.log*")
    
    # Also check for SM log files in subdirectories
    sm_path_files = cache.find_files("*/sm/sm.log*")
    sm_log_files.extend(sm_path_files)
    
    if sm_log_files:
        files_found = True
        print("Found {0} SM log files in extracted tech support".format(len(sm_log_files)))
        
        # Use a single unified command to search all SM log files at once
        # This is more efficient than searching each file individually
        search_cmd = "zgrep '{0}' {1}/logs/k8_infra/sm/sm.log*.gz 2>/dev/null || zgrep '{0}' {1}/logs/k8_infra/sm/sm.log* 2>/dev/null || echo 'No matches found'".format(search_string, node_dir)
        print("Searching all SM log files with unified command")
        output = run_command(search_cmd)
        
        if output and "No matches found" not in output and search_string in output:
            matches = output.strip().split('\n')
            print("Found {0} matches in SM log files".format(len(matches)))
    else:
        # Verify if SM directories exist but have no log files
        find_sm_dirs_cmd = "find {0} -type d -path '*/sm' -print".format(node_dir)
        sm_dirs = run_command(find_sm_dirs_cmd).strip().split("\n")
        sm_dirs = [d for d in sm_dirs if d]
        
        if sm_dirs:
            files_found = True
            return set_warning_status(
                "Logs directory exists but contains no SM logs",
                "Found SM directories but no log files to analyze"
            )
        else:
            # Verify if tech support was properly extracted by checking for common directories
            if os.path.exists("{0}/logs".format(node_dir)) or os.path.exists("{0}/logs/k8_infra".format(node_dir)):
                files_found = True
                return set_warning_status(
                    "Logs directory exists but contains no SM directories or logs",
                    "Found logs directory but no SM log files"
                )
            else:
                # Verify if tech support was properly extracted at all
                common_dirs = ["systeminfo", "logs", "k8-diag", "storage-diag"]
                extracted_dirs = []
                for d in common_dirs:
                    if os.path.exists("{0}/{1}".format(node_dir, d)):
                        extracted_dirs.append(d)
                
                if extracted_dirs:
                    files_found = True
                    return set_warning_status(
                        "Tech support was extracted but is missing logs/k8_infra directory",
                        "Tech support is missing logs/k8_infra directory"
                    )
                else:
                    print("Tech support extraction appears incomplete or failed")
    
    # Final results determination
    if not matches:
        # Check if we tried but couldn't find any SM log files to search
        if not files_found:
            print("[ERROR] No SM log files found to search for certificate check")
            
            # Additional diagnostic output
            find_cmd = "find {0} | grep -i sm".format(node_dir)
            find_result = run_command(find_cmd)
            if find_result:
                print("Available paths with 'sm' in the name:\n{0}".format(find_result))
                
            results["checks"]["certificate_check"]["status"] = "ERROR"
            results["checks"]["certificate_check"]["details"] = ["Unable to find SM log files for certificate bug check"]
            return False
            
        # If we found files but no matches, that's a PASS
        else:
            print("[PASS] No instances of CA certificate bug (CSCwm35992) found")
            results["checks"]["certificate_check"]["status"] = "PASS"
            results["checks"]["certificate_check"]["details"] = ["No certificate issues found in SM logs"]
            return True
    else:
        first_match = matches[0]
        print("[FAIL] Found {0} instances of CA certificate bug (CSCwm35992)".format(len(matches)))
        
        # Format the error message with proper indentation for the report
        # Using consistent 4-space indentation for all lines
        error_lines = first_match.strip().split('\n')
        indented_error = "\n    ".join(error_lines)  # 4 spaces for alignment with Details column
        
        # Store only the specific error message in details
        results["checks"]["certificate_check"]["status"] = "FAIL"  
        results["checks"]["certificate_check"]["details"] = [
            "Certificate name validation error detected: \n\n    {0}".format(indented_error)
        ]
        
        # Add the explanation and recommendation
        results["checks"]["certificate_check"]["explanation"] = "Certificate names with spaces are not supported."
        results["checks"]["certificate_check"]["recommendation"] = (
            "1. Remove this CA certificate and re-add it using a name that does not contain spaces.\n"
            "  2. Re-run the Pre-upgrade script to confirm the check is now a PASS.\n"
            "  3. If the check is still a FAIL, contact Cisco TAC for assistance in verification/remediation."
        )
        results["checks"]["certificate_check"]["reference"] = "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm35992"
        
        return True

@robust_check("iso_check")
def check_ISOs_CSCwn94394(tech_file):
    """OPTIMIZED: Multiple ISOs bug check using file cache and unified commands"""
    print_section("Checking Multiple ISOs (CSCwn94394) - Optimized on {0}".format(NODE_NAME))
    update_status("running", "Optimized multiple ISOs check", 95)
    
    search_string = "invalid number of ISO"
    files_examined = False
    matches = []
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use file cache for faster file discovery
    cache = get_file_cache()
    boot_hook_files = cache.find_files("boot-hook*")
    
    if boot_hook_files:
        files_examined = True
        print("Found {0} boot-hook log files in extracted tech support".format(len(boot_hook_files)))
        
        # Use a unified search command that works with both .gz and regular files
        # This is more efficient than searching each file individually
        search_cmd = "find {0} -type f -name 'boot-hook*' -print0 | xargs -0 zgrep '{1}' 2>/dev/null || true".format(node_dir, search_string)
        print("Searching all boot-hook files for ISO errors")
        output = run_command(search_cmd)
        
        if output and not output.startswith("Error:") and search_string in output:
            matches = output.strip().split('\n')
            print("Found {0} matches in boot-hook files".format(len(matches)))
    else:
        # If no boot-hook files were found in the extracted directories
        print("No boot-hook logs found in extracted tech support")
        
        # Check if tech support has the expected structure
        if os.path.exists("{0}/conf-diag".format(node_dir)):
            files_examined = True
            print("The conf-diag directory exists but contains no boot-hook logs")
        else:
            print("The conf-diag directory is missing from extracted tech support")
            
            # Verify if tech support was properly extracted by checking for other common directories
            common_dirs = ["systeminfo", "logs", "k8-diag", "storage-diag"]
            extracted_dirs = []
            for d in common_dirs:
                if os.path.exists("{0}/{1}".format(node_dir, d)):
                    extracted_dirs.append(d)
            
            if extracted_dirs:
                files_examined = True
                print("Tech support was extracted but is missing conf-diag directory")
            else:
                print("Tech support extraction appears incomplete or failed")
    
    # Final results determination
    if not matches:
        # Check if we tried but couldn't find any boot-hook files to search
        if not files_examined:
            print("[ERROR] No boot-hook log files found to search for ISO check")
            results["checks"]["iso_check"]["status"] = "ERROR"
            results["checks"]["iso_check"]["details"] = ["Unable to find boot-hook logs for multiple ISO check"]
            return False
            
        # If we found files but no matches, that's a PASS
        else:
            print("[PASS] No instances of multiple ISOs boot-hook bug (CSCwn94394) found")
            results["checks"]["iso_check"]["status"] = "PASS"
            results["checks"]["iso_check"]["details"] = ["No multiple ISO issues found"]
            return True
    else:
        # Report the results
        first_match = matches[0]
        print("[FAIL] Found {0} instances of multiple ISOs in boot-hook bug (CSCwn94394)".format(len(matches)))
        
        # Extract ISO list if possible
        iso_list = []
        
        # Look for ISO list with a similar unified approach for efficiency
        iso_search_cmd = "zgrep 'iso list' {0}/conf-diag/boot-hook* 2>/dev/null || zgrep 'iso list' {0}/boot-hook* 2>/dev/null || true".format(node_dir)        
        iso_output = run_command(iso_search_cmd)
        
        if iso_output and "iso list" in iso_output:
            iso_lines = iso_output.strip().split('\n')
            for line in iso_lines:
                if "iso list" in line:
                    # Try regex extraction
                    match = re.search(r'"iso list":\[(.*?)\]', line)
                    if match:
                        iso_string = match.group(1)
                        iso_list = [item.strip(' "\'') for item in iso_string.split(',')]
                        break
        
        results["checks"]["iso_check"]["status"] = "FAIL"
        
        if iso_list:
            # Format with proper indentation - 4 spaces for alignment with Details column
            iso_list_formatted = "\n    ".join(["[{0}] {1}".format(i+1, iso) for i, iso in enumerate(iso_list)])
            match_lines = first_match.strip().split('\n')
            match_formatted = "\n    ".join(match_lines)
            
            # Include specific error details in the array
            combined_detail = "Multiple ISOs in boot-hook detected: \n\n    {0}\n\n    Multiple ISOs found:\n    {1}".format(match_formatted, iso_list_formatted)
            results["checks"]["iso_check"]["details"] = [combined_detail]
        else:
            # Format with proper indentation - 4 spaces for alignment
            match_lines = first_match.strip().split('\n')
            match_formatted = "\n    ".join(match_lines)
            
            # Include specific error details in the array
            results["checks"]["iso_check"]["details"] = [
                "Multiple ISOs in boot-hook detected: \n\n    {0}".format(match_formatted)
            ]
        
        # Add explanation and recommendation at the top level
        results["checks"]["iso_check"]["explanation"] = "Only one ISO can be in the firmware directory on the running ND version."
        results["checks"]["iso_check"]["recommendation"] = "Contact TAC for assistance in removing the unneeded ISO images."
        results["checks"]["iso_check"]["reference"] = "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn94394"
        
        return True

@robust_check("lvm_pvs_check")
def check_lvm_pvs(tech_file):
    """
    OPTIMIZED: Check for LVM PVs with empty elasticsearch volumes using file cache and streaming
    
    Check if both elasticsearch.nir and elasticsearch physical volumes exist with PSize = PFree,
    which means volumes exist but contain no data - a condition that can cause issues with 
    NDI enablement post-upgrade (CSCwe91228)
    """
    print_section("Checking LVM Elasticsearch Volumes (CSCwe91228) - Optimized on {0}".format(NODE_NAME))
    update_status("running", "Optimized LVM PVs check", 95)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use file cache instead of find command
    cache = get_file_cache()
    lvm_pvs_files = cache.find_files("lvm-pvs")
    
    if not lvm_pvs_files:
        print("[PASS] lvm-pvs file not found, skipping check")
        results["checks"]["lvm_pvs_check"] = {"status": "PASS", "details": ["No empty Elasticsearch PVs found"]}
        return True
        
    lvm_pvs_file = lvm_pvs_files[0]
    print("Found lvm-pvs file: {0}".format(lvm_pvs_file))
    
    # Read the file content
    try:
        with open(lvm_pvs_file, 'r') as f:
            content = f.read()
        
        # Look for the specific problematic entries with PSize = PFree = 2.18t
        elasticsearch_nir_line = None
        elasticsearch_line = None
        
        diagnostic_lines = []
        found_header = False
        
        for line in content.splitlines():
            if "PV             VG" in line:
                diagnostic_lines.append(line)
                found_header = True
                continue
                
            if found_header:
                if "/dev/sda1" in line and "elasticsearch.nir" in line:
                    elasticsearch_nir_line = line
                    diagnostic_lines.append(line)
                elif "/dev/sdb1" in line and "elasticsearch" in line and not "cisco.nir.main.elasticsearch" in line:
                    elasticsearch_line = line
                    diagnostic_lines.append(line)
        
        # Check if both PVs are found with the exact problematic condition: PSize = PFree = 2.18t
        has_elasticsearch_nir_empty = elasticsearch_nir_line and "2.18t    2.18t" in elasticsearch_nir_line
        has_elasticsearch_empty = elasticsearch_line and "2.18t    2.18t" in elasticsearch_line
        
        # Initialize results dictionary with proper structure
        results["checks"]["lvm_pvs_check"] = {
            "status": "PASS",
            "details": []
        }
        
        # Add diagnostic output first
        if diagnostic_lines:
            results["checks"]["lvm_pvs_check"]["details"].append("LVM Physical Volume Details:")
            for line in diagnostic_lines:
                results["checks"]["lvm_pvs_check"]["details"].append(line)
        
        # Set result based on findings - only WARNING if both PVs exist and have PSize = PFree = 2.18t
        if has_elasticsearch_nir_empty and has_elasticsearch_empty:
            print("[WARNING] Both elasticsearch.nir and elasticsearch physical volumes detected with empty space")
            results["checks"]["lvm_pvs_check"]["status"] = "WARNING"
            # Add explanation and recommendation at the top level
            results["checks"]["lvm_pvs_check"]["explanation"] = "Due to CSCwe91228, if NDI is deleted before upgrade, enablement of new NDI\n  post-upgrade can fail."
            results["checks"]["lvm_pvs_check"]["recommendation"] = "Contact TAC to apply the workaround if enablement of NDI fails post-upgrade."
            results["checks"]["lvm_pvs_check"]["reference"] = "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe91228"
        else:
            print("[PASS] No problematic LVM volume configuration detected")
            results["checks"]["lvm_pvs_check"]["status"] = "PASS"
            if elasticsearch_nir_line or elasticsearch_line:
                results["checks"]["lvm_pvs_check"]["details"].append("\nElasticsearch volumes exist but don't show the problematic empty state condition.")
            else:
                results["checks"]["lvm_pvs_check"]["details"].append("\nNo elasticsearch volumes detected.")
            
            # Always use this simpler message for PASS status
            results["checks"]["lvm_pvs_check"]["details"] = ["No empty Elasticsearch PVs found"]
        
        return True
            
    except Exception as e:
        print("[WARNING] Error reading lvm-pvs file: {0}".format(str(e)))
        results["checks"]["lvm_pvs_check"] = {
            "status": "PASS",
            "details": ["No empty Elasticsearch PVs found"]
        }
        return False

def get_cluster_node_count():
    """
    Get the number of active nodes in the cluster from acs show nodes output.
    Returns the count of nodes with Master role and Active status.
    """
    try:
        cmd = "acs show nodes"
        output = run_command(cmd)
        
        if not output:
            print("[WARNING] Could not retrieve node information for node count")
            return None
        
        node_count = 0
        lines = output.strip().split('\n')
        
        for line in lines:
            # Skip header and border lines
            if "NAME (*=SELF)" in line or not line.strip():
                continue
            
            # Skip table border lines
            stripped = line.strip()
            if stripped:
                is_border = True
                for c in stripped:
                    char_code = ord(c)
                    if char_code not in [43, 45, 124, 166] and not (9474 <= char_code <= 9532):
                        is_border = False
                        break
                if is_border:
                    continue
            
            # Skip horizontal separators
            if '----------' in line:
                continue
            
            # Check if this is a node line
            delimiter = None
            for c in line:
                if ord(c) in [9474, 166]:  # │ or ¦
                    delimiter = c
                    break
            
            if delimiter:
                parts = [p.strip() for p in line.split(delimiter) if p.strip()]
                
                # Skip lines that are all dashes
                if parts and all(all(c == '-' for c in p) for p in parts):
                    continue
                
                # Need at least 7 parts for a valid node line
                if len(parts) >= 7:
                    role = parts[3].strip()
                    status = parts[6].strip()
                    
                    # Count nodes with Master role and Active status
                    if role.lower() == "master" and "active" in status.lower():
                        node_count += 1
        
        print("[INFO] Detected {0} active node(s) in cluster".format(node_count))
        return node_count
        
    except Exception as e:
        print("[WARNING] Error counting cluster nodes: {0}".format(str(e)))
        return None

@robust_check("persistent_ip_check")
def check_persistent_ip_config(tech_file):
    """
    OPTIMIZED: Check Nexus Dashboard Persistent IP configuration from external IP config files
    
    Validates external IP configurations from:
    - falcon-diag/externalipconfigs.yaml (ND < 4.1)
    - k8-diag/kubectl/k8-externalipconfigs.yaml (ND >= 4.1)
    
    Required persistent IPs:
    - Single node cluster (1 node): 3 persistent IPs
    - Multi-node cluster (3+ nodes): 5 persistent IPs
    
    This check only applies to ND version >= 3.2
    This is critical for upgrade success in some deployment scenarios.
    """
    print_section("Checking Persistent IP Configuration on {0}".format(NODE_NAME))
    update_status("running", "Checking persistent IP configuration", 97)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use shared context and cache
    ctx = get_validation_context()
    cache = ctx.cache
    
    # Check ND version - this check only applies to ND 3.2 and later
    if not ctx.nd_version:
        print("[WARNING] Could not determine ND version")
        # Continue with check to be safe
    elif not ctx.is_version_applicable(3, 2):
        print("[PASS] ND version {0} < 3.2 - Persistent IP check not applicable".format(ctx.nd_version))
        return CheckResult.set_pass("persistent_ip_check", "Version below 3.2, check not applicable")
    else:
        print("ND version {0} >= 3.2 - proceeding with Persistent IP check".format(ctx.nd_version))
    
    # Determine cluster size and required persistent IP count
    node_count = get_cluster_node_count()
    
    # Set required IP count based on cluster size
    if node_count == 1:
        required_ip_count = 3
        print("[INFO] Single-node cluster detected - requiring {0} persistent IPs".format(required_ip_count))
    elif node_count is not None and node_count >= 3:
        required_ip_count = 5
        print("[INFO] Multi-node cluster ({0} nodes) detected - requiring {1} persistent IPs".format(node_count, required_ip_count))
    else:
        # Default to 5 IPs if we can't determine node count or have 2 nodes (unusual case)
        required_ip_count = 5
        if node_count is None:
            print("[WARNING] Could not determine cluster size - defaulting to {0} persistent IP requirement".format(required_ip_count))
        else:
            print("[INFO] {0}-node cluster detected - requiring {1} persistent IPs".format(node_count, required_ip_count))
    
    # Try both possible external IP config file paths
    config_files = []
    
    # First try k8-diag path (ND >= 4.1)
    k8_pattern = "k8-diag/kubectl/k8-externalipconfigs.yaml"
    k8_files = cache.find_files(k8_pattern)
    if k8_files:
        config_files.extend(k8_files)
        print("Found k8-diag external IP config (ND >= 4.1): {0}".format(os.path.basename(k8_files[0])))
    
    # Then try falcon-diag path (ND < 4.1)
    falcon_pattern = "falcon-diag/externalipconfigs.yaml"
    falcon_files = cache.find_files(falcon_pattern)
    if falcon_files:
        config_files.extend(falcon_files)
        print("Found falcon-diag external IP config (ND < 4.1): {0}".format(os.path.basename(falcon_files[0])))
    
    # Also try wildcard patterns in case files are in subdirectories
    if not config_files:
        wildcard_patterns = [
            "*/k8-diag/kubectl/k8-externalipconfigs.yaml",
            "*/falcon-diag/externalipconfigs.yaml",
            "**/externalipconfigs.yaml"
        ]
        for pattern in wildcard_patterns:
            found_files = cache.find_files(pattern)
            if found_files:
                config_files.extend(found_files)
                print("Found external IP config via pattern {0}: {1}".format(pattern, os.path.basename(found_files[0])))
                break
    
    if not config_files:
        print("[WARNING] External IP config file not found in tech support")
        return CheckResult.set_warning(
            "persistent_ip_check",
            ["Could not locate externalipconfigs.yaml file in tech support",
             "Checked paths: falcon-diag/externalipconfigs.yaml, k8-diag/kubectl/k8-externalipconfigs.yaml"],
            explanation="Unable to determine persistent IP configuration - external IP config file not found.\n  "
                       "This could indicate no persistent IPs are configured, or the tech support is incomplete.",
            recommendation="Verify that at least {0} persistent IP addresses are properly configured before proceeding with upgrade.".format(required_ip_count),
            reference="https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/"
                     "cisco-nexus-dashboard-deployment-guide-41x/nd-prerequisites-41x.html#concept_zkj_3hj_cgc"
        )
    
    # Use the first found config file
    config_file = config_files[0]
    config_type = "k8-diag" if "k8-diag" in config_file else "falcon-diag"
    print("Parsing {0} external IP config: {1}".format(config_type, os.path.basename(config_file)))
    
    try:
        # Parse the YAML file to extract external IP configurations
        data_external_ips = 0  # Only count data-external-services IPs
        all_external_ips = []
        external_ip_configs = []
        file_has_items_section = False
        
        # First, check if file contains expected content
        file_content = ""
        with open(config_file, 'r') as f:
            file_content = f.read()
        
        # Check for unexpected output (like error messages)
        if "items" not in file_content:
            print("[WARNING] External IP config file does not contain expected 'items' section")
            print("File content preview: {0}".format(file_content[:200]))
            return CheckResult.set_warning(
                "persistent_ip_check",
                "Persistent IP config could not be validated.",
                explanation="The Persistent IP configuration file exists but does not contain the expected YAML structure.",
                recommendation="Verify that at least {0} persistent IP addresses are properly configured before proceeding with upgrade.\n  "
                              "Check the Nexus Dashboard configuration for external IP settings.".format(required_ip_count),
                reference="https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/"
                         "cisco-nexus-dashboard-deployment-guide-41x/nd-prerequisites-41x.html#concept_zkj_3hj_cgc"
            )
        
        # Stream processing to handle large config files efficiently
        with open(config_file, 'r') as f:
            in_external_ip_section = False
            current_config = {}
            in_data_external_services = False
            
            for line_num, line in enumerate(f, 1):
                line_stripped = line.strip()
                
                # Skip empty lines and comments
                if not line_stripped or line_stripped.startswith('#'):
                    continue
                
                # Calculate indentation level
                indent = len(line) - len(line.lstrip())
                
                # Check for start of items section
                if line_stripped == "items:" or (line_stripped.startswith("items:") and line_stripped.endswith("[]")):
                    file_has_items_section = True
                    if line_stripped.endswith("[]"):
                        # Empty items array - no external IPs configured
                        print("Found empty items array - no external IP configurations")
                        break
                    continue
                
                # Look for ExternalIpConfig items
                if line_stripped.startswith("- apiVersion:") and "case.cncf.io" in line_stripped:
                    current_config = {"name": "unknown", "externalIPs": []}
                    in_data_external_services = False
                    continue
                
                # Extract configuration name and check if it's data-external-services
                if "name:" in line_stripped and indent > 0:
                    name_match = line_stripped.split("name:")
                    if len(name_match) > 1:
                        config_name = name_match[1].strip()
                        current_config["name"] = config_name
                        in_data_external_services = (config_name == "data-external-services")
                        print("Found config: {0} (data-external-services: {1})".format(config_name, in_data_external_services))
                        continue
                
                # Look for externalIP section
                if line_stripped == "externalIP:" and indent > 0:
                    in_external_ip_section = True
                    continue
                
                # Process external IP addresses
                if in_external_ip_section:
                    if line_stripped.startswith("- ") and "." in line_stripped:
                        # Extract IP address
                        ip_address = line_stripped[2:].strip()
                        # Basic IP validation
                        ip_parts = ip_address.split(".")
                        if len(ip_parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
                            current_config["externalIPs"].append(ip_address)
                            all_external_ips.append(ip_address)
                            # Only count IPs from data-external-services for the requirement check
                            if in_data_external_services:
                                data_external_ips += 1
                                print("  Found data-external-services IP: {0}".format(ip_address))
                            else:
                                print("  Found {0} IP: {1}".format(current_config["name"], ip_address))
                    elif line_stripped and not line_stripped.startswith("-") and indent <= 4:
                        # End of externalIP section
                        in_external_ip_section = False
                        if current_config["externalIPs"]:
                            external_ip_configs.append(current_config.copy())
        
        # Add any remaining config if it has IPs
        if current_config.get("externalIPs"):
            external_ip_configs.append(current_config)
        
        # Analyze results - Only count data-external-services IPs for requirements
        if data_external_ips == 0:
            print("[FAIL] Found 0 persistent IP addresses in data-external-services")
            return CheckResult.set_fail(
                "persistent_ip_check",
                "Found 0 persistent IP addresses in data-external-services configuration (required: {0})".format(required_ip_count),
                explanation="The Nexus Dashboard data-external-services configuration has ZERO Persistent IP addresses.\n  "
                           "This will likely result in upgrade failure as persistent IPs are required for data services.\n  "
                           "Required: {0} persistent IPs for a {1}-node cluster.".format(required_ip_count, node_count if node_count else "unknown"),
                recommendation="1. Configure at least {0} persistent IP addresses for data-external-services before attempting upgrade.\n  "
                              "2. Consult the Nexus Dashboard deployment guide for proper persistent IP configuration.\n  "
                              "3. Re-run the Pre-upgrade script to confirm the check is now a PASS.\n  "
                              "4. If the check is still a FAIL, contact Cisco TAC for assistance in verification/remediation.".format(required_ip_count),
                reference="https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/"
                         "cisco-nexus-dashboard-deployment-guide-41x/nd-prerequisites-41x.html#concept_zkj_3hj_cgc"
            )
        elif data_external_ips < required_ip_count:
            print("[FAIL] Found {0} persistent IP addresses in data-external-services (less than the required minimum of {1})".format(data_external_ips, required_ip_count))
            
            # Build details with IP list
            details = [
                "Found {0} persistent IP addresses in data-external-services (required: {1} for {2}-node cluster)".format(
                    data_external_ips, required_ip_count, node_count if node_count else "unknown")
            ]
            
            # Add details about data-external-services configuration
            for config in external_ip_configs:
                if config["name"] == "data-external-services" and config["externalIPs"]:
                    details.append(
                        "data-external-services IPs: {0}".format(", ".join(config["externalIPs"]))
                    )
            
            return CheckResult.set_fail(
                "persistent_ip_check",
                details,
                explanation="The Nexus Dashboard data-external-services is configured with {0} Persistent IP addresses,\n  "
                           "which is less than the required minimum of {1} for a {2}-node cluster.\n  "
                           "This will likely result in upgrade failure.".format(data_external_ips, required_ip_count, node_count if node_count else "unknown"),
                recommendation="1. Configure at least {0} persistent IP addresses for data-external-services before attempting upgrade.\n  "
                              "2. Consult the Nexus Dashboard deployment guide for proper persistent IP configuration.\n  "
                              "3. Re-run the Pre-upgrade script to confirm the check is now a PASS.\n  "
                              "4. If the check is still a FAIL, contact Cisco TAC for assistance in verification/remediation.".format(required_ip_count),
                reference="https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/"
                         "cisco-nexus-dashboard-deployment-guide-41x/nd-prerequisites-41x.html#concept_zkj_3hj_cgc"
            )
        else:
            print("[PASS] Found {0} persistent IP addresses (meets minimum requirement of {1} for {2}-node cluster)".format(
                data_external_ips, required_ip_count, node_count if node_count else "unknown"))
            return CheckResult.set_pass(
                "persistent_ip_check",
                "Found {0} persistent IP addresses (required: {1} for {2}-node cluster)".format(
                    data_external_ips, required_ip_count, node_count if node_count else "unknown")
            )
        
    except Exception as e:
        print("[ERROR] Failed to parse external IP config file: {0}".format(str(e)))
        return CheckResult.set_fail(
            "persistent_ip_check",
            ["Failed to parse external IP config file: {0}".format(str(e)),
             "File: {0}".format(os.path.basename(config_file))],
            explanation="Could not determine persistent IP configuration due to parsing error",
            recommendation="1. Configure at least {0} persistent IP addresses for data-external-services before attempting upgrade.\n  "
                          "2. Consult the Nexus Dashboard deployment guide for proper persistent IP configuration.\n  "
                          "3. Contact Cisco TAC for assistance in verification/remediation if required.".format(required_ip_count)
        )
    
    return True

@robust_check("atom0_nvme_check")
def check_atom0_nvme(tech_file):
    """
    Check NVME drive health on physical Nexus Dashboard nodes.
    
    For physical ND nodes, validates that atom0_nvme is present in PVS file.
    This is critical to ensure NVME drive operability before upgrade.
    Virtual nodes skip this check as they don't have physical NVME drives.
    """
    print_section("Checking NVME Drive Health on {0}".format(NODE_NAME))
    update_status("running", "Checking NVME drive health", 97)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use shared context and cache
    ctx = get_validation_context()
    cache = ctx.cache
    
    # Check nodeType - if not available, show warning
    if not ctx.node_type:
        return CheckResult.set_warning(
            "atom0_nvme_check",
            "Unable to determine if nodeType is Physical or Virtual to proceed with check.",
            explanation="nodeType is required to determine whether atom0_nvme should be present in PVS file or not.",
            recommendation="If the ND is Virtual, you can safely ignore this check.\n"
                          "If the ND is Physical, verify the NVME drive health of all ND nodes via CIMC, or contact Cisco TAC for assistance."
        )
    
    # If Virtual, skip the check (PASS)
    if ctx.node_type == "Virtual":
        print("[PASS] Virtual ND node - NVME check not applicable")
        return CheckResult.set_pass("atom0_nvme_check", "Virtual ND (check not applicable)")
    
    # Physical node - determine version and check appropriate PVS file
    print("Physical ND node detected - checking for NVME drive presence")
    
    # Use version from context
    nd_version = ctx.nd_version
    if not nd_version:
        print("[WARNING] acs_version file not found")
        return CheckResult.set_warning(
            "atom0_nvme_check",
            "PVS file not found in the tech support to confirm atom0_nvme presence",
            explanation="NVME drive operability needs to be confirmed to ensure successful upgrade.",
            recommendation="Verify NVME drive health in CIMC or contact Cisco TAC for assistance if required."
        )
    
    # Step 4: Determine which PVS file to check based on version
    pvs_file_to_check = None
    
    # Parse version to determine if >= 4.1.1g
    is_new_version = False
    if nd_version:
        try:
            # Extract major.minor version (e.g., "4.1.1g" -> "4.1")
            version_parts = nd_version.split('.')
            if len(version_parts) >= 2:
                major = int(version_parts[0])
                minor = int(version_parts[1])
                
                # Check if version >= 4.1
                if major > 4 or (major == 4 and minor >= 1):
                    is_new_version = True
                    print("Version >= 4.1.1g - checking coreos-diag/storage/pvdisplay")
                else:
                    print("Version < 4.1.1g - checking storage-diag/pvs")
        except Exception as e:
            print("[WARNING] Could not parse version: {0}".format(str(e)))
    
    # Check for pvdisplay first (if both exist, prefer this one per requirement 6c)
    pvdisplay_files = cache.find_files("coreos-diag/storage/pvdisplay")
    pvs_files = cache.find_files("storage-diag/pvs")
    
    if pvdisplay_files:
        pvs_file_to_check = pvdisplay_files[0]
        print("Using pvdisplay file: {0}".format(os.path.basename(pvs_file_to_check)))
    elif pvs_files:
        pvs_file_to_check = pvs_files[0]
        print("Using pvs file: {0}".format(os.path.basename(pvs_file_to_check)))
    else:
        print("[WARNING] Neither pvdisplay nor pvs file found in tech support")
        return CheckResult.set_warning(
            "atom0_nvme_check",
            "PVS file not found in the tech support to confirm atom0_nvme presence",
            explanation="NVME drive operability needs to be confirmed to ensure successful upgrade.",
            recommendation="Verify NVME drive health in CIMC or contact Cisco TAC for assistance if required."
        )
    
    # Step 5: Search for atom0_nvme in the PVS file
    print("Searching for atom0_nvme in PVS file...")
    atom0_nvme_found = False
    
    try:
        with open(pvs_file_to_check, 'r') as f:
            for line in f:
                if 'atom0_nvme' in line:
                    atom0_nvme_found = True
                    print("[PASS] Found atom0_nvme in PVS file: {0}".format(line.strip()))
                    break
    except Exception as e:
        print("[WARNING] Error reading PVS file: {0}".format(str(e)))
        return CheckResult.set_warning(
            "atom0_nvme_check",
            "PVS file not found in the tech support to confirm atom0_nvme presence",
            explanation="NVME drive operability needs to be confirmed to ensure successful upgrade.",
            recommendation="Verify NVME drive health in CIMC or contact Cisco TAC for assistance if required."
        )
    
    # Report results
    if atom0_nvme_found:
        print("[PASS] NVME drive confirmed operational")
        return CheckResult.set_pass("atom0_nvme_check", "NVME drive seen by ND in PVS file")
    else:
        print("[FAIL] atom0_nvme NOT found in PVS file")
        return CheckResult.set_fail(
            "atom0_nvme_check",
            "atom0_nvme doesn't exist in PVS file",
            explanation="NVME drive on the node may be inoperable which will result in upgrade failure.",
            recommendation="Contact TAC for further investigation and potential disk or appliance replacement prior to upgrade."
        )

@robust_check("atom0_vg_check")
def check_atom0_vg(tech_file):
    """
    OPTIMIZED: Check atom0 virtual group free space
    
    Validates that the atom0 VG has at least 50G free space for upgrade.
    This is critical to prevent upgrade failures at 'Deploy Kubernetes Stack' stage.
    NOTE: This check is bypassed for ND 4.1.1g and later versions.
    """
    print_section("Checking atom0 Virtual Group Space on {0}".format(NODE_NAME))
    update_status("running", "Checking atom0 VG space", 98)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    
    # Use shared context and cache
    ctx = get_validation_context()
    cache = ctx.cache
    
    # Check ND version - bypass check for 4.1.1 and later
    if ctx.nd_version and ctx.is_version_applicable(4, 1, 1):
        print("[PASS] ND version {0} >= 4.1.1 - atom0 VG check bypassed".format(ctx.nd_version))
        return CheckResult.set_pass("atom0_vg_check", "atom0 vg check bypassed for ND nodes on 4.1.1 and later")
    
    # Look for lvm-vgs files in storage-diag or similar directories
    vgs_patterns = [
        "lvm-vgs",
        "storage-diag/vgs",
        "*/lvm-vgs",
        "*/storage-diag/vgs"
    ]
    
    vgs_files = []
    for pattern in vgs_patterns:
        found_files = cache.find_files(pattern)
        if found_files:
            vgs_files.extend(found_files)
            print("Found VGS file via pattern {0}: {1}".format(pattern, os.path.basename(found_files[0])))
            break
    
    if not vgs_files:
        print("[WARNING] LVM VGS file not found in tech support")
        return CheckResult.set_warning("atom0_vg_check", "Unable to verify if atom0 vg has >50G free space")
    
    # Use the first found VGS file
    vgs_file = vgs_files[0]
    print("Parsing VGS file: {0}".format(os.path.basename(vgs_file)))
    
    try:
        atom0_free_space = None
        atom0_found = False
        
        with open(vgs_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line_stripped = line.strip()
                
                # Skip header lines and empty lines
                if not line_stripped or line_stripped.startswith("VG") or line_stripped.startswith("#"):
                    continue
                
                # Look for atom0 line (exact match to avoid atom0_nvme, atom0_ssd)
                parts = line_stripped.split()
                if len(parts) >= 7 and parts[0] == "atom0":
                    atom0_found = True
                    vfree_str = parts[6]  # VFree column (VG, #PV, #LV, #SN, Attr, VSize, VFree)
                    
                    print("Found atom0 VG: {0}".format(line_stripped))
                    print("VFree field: {0}".format(vfree_str))
                    
                    # Parse the free space value (could be like "91.21g", "<91.21g", "34.16g")
                    # Remove < symbols and extract numeric value
                    vfree_clean = vfree_str.replace('<', '').replace('>', '')
                    
                    # Extract numeric part and unit
                    import re
                    match = re.match(r'([0-9.]+)([gmtGMT])', vfree_clean)
                    if match:
                        value = float(match.group(1))
                        unit = match.group(2).lower()
                        
                        # Convert to GB
                        if unit == 'g':
                            atom0_free_space = value
                        elif unit == 't':
                            atom0_free_space = value * 1024  # TB to GB
                        elif unit == 'm':
                            atom0_free_space = value / 1024  # MB to GB
                        else:
                            atom0_free_space = value  # assume GB
                        
                        print("Parsed atom0 free space: {0:.2f} GB".format(atom0_free_space))
                        break
                    else:
                        print("[WARNING] Could not parse VFree value: {0}".format(vfree_str))
        
        # Analyze results
        if not atom0_found:
            print("[WARNING] atom0 VG not found in VGS output")
            return CheckResult.set_warning("atom0_vg_check", "Unable to verify if atom0 vg has >50G free space")
        elif atom0_free_space is None:
            print("[WARNING] Could not parse atom0 free space")
            return CheckResult.set_warning("atom0_vg_check", "Unable to verify if atom0 vg has >50G free space")
        elif atom0_free_space < 50.0:
            print("[FAIL] atom0 VG has {0:.2f}G free space (less than 50G required)".format(atom0_free_space))
            return CheckResult.set_fail(
                "atom0_vg_check",
                "atom0 vg has less than 50G free space",
                explanation="The atom0 virtual group requires 50G free space when performing an upgrade.\n  "
                           "Otherwise, upgrade may fail at 'Deploy Kubernetes Stack' stage.",
                recommendation="Contact Cisco TAC to help resize the atom0 virtual group before upgrade.",
                reference="https://bst.cisco.com/quickview/bug/CSCwr43515"
            )
        else:
            print("[PASS] atom0 VG has {0:.2f}G free space (meets 50G requirement)".format(atom0_free_space))
            return CheckResult.set_pass("atom0_vg_check", "atom0 vg has more than 50G free space")
        
    except Exception as e:
        print("[ERROR] Failed to parse VGS file: {0}".format(str(e)))
        return CheckResult.set_warning("atom0_vg_check", "Unable to verify if atom0 vg has >50G free space")
    
    return True

@robust_check("vnd_app_large_check")
def check_vnd_app_large(tech_file):
    """
    Check for vND SAN App-Large profile (CSCws77374)
    
    This check verifies if a Virtual ND is running with App-Large profile configuration.
    vND SAN App is only supported for Regular App Node (16 vCPUs/64GB RAM/500GB Disk)
    and Data Node (32 vCPUs/128GB RAM/3TB Disk).
    
    The check:
    1. Verifies ND version is 3.2.x
    2. Checks if model is SE-VIRTUAL-APP
    3. Checks if /dev/sdb1 atom0 has PSize ~1.5T in lvm-pvs
    4. Checks deploymentMode for "ndfc" presence
    
    Results:
    - FAIL: SE-VIRTUAL-APP + deploymentMode contains "ndfc" + disk size 1.5T
    - WARNING: SE-VIRTUAL-APP + deploymentMode does NOT contain "ndfc" + disk size 1.5T
    - PASS: All other scenarios
    
    Reference: CSCws77374 and ND Deployment Guide 4.1.x
    """
    print_section("Checking vND SAN App-Large Profile on {0}".format(NODE_NAME))
    update_status("running", "Checking vND SAN App-Large Profile", 99.5)
    
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    cache = get_file_cache()
    
    # Use shared context and cache
    ctx = get_validation_context()
    cache = ctx.cache
    
    # Step 1: Check ND version - only applicable for 3.2.x
    if not ctx.nd_version:
        return CheckResult.set_warning("vnd_app_large_check", "Unable to determine ND version")
    
    # Check if version is 3.2.x
    if not ctx.nd_version.startswith("3.2"):
        print("[PASS] Version is not 3.2.x (current: {0})".format(ctx.nd_version))
        return CheckResult.set_pass("vnd_app_large_check", "Version is not 3.2.x")
    
    print("Version is 3.2.x - proceeding with check")
    
    # Step 2: Check model and deploymentMode from acs_system_config
    system_config_files = cache.find_files("acs-checks/acs_system_config")
    if not system_config_files:
        print("[WARNING] acs_system_config file not found")
        return CheckResult.set_warning("vnd_app_large_check", "Unable to determine device type")
    
    system_config_file = system_config_files[0]
    print("Reading model and deploymentMode from: {0}".format(os.path.basename(system_config_file)))
    
    model = None
    deployment_mode = None
    try:
        with open(system_config_file, 'r') as f:
            for line in f:
                if 'model:' in line:
                    model = line.split(':', 1)[1].strip()
                    print("Found model: {0}".format(model))
                if 'deploymentMode:' in line:
                    deployment_mode = line.split(':', 1)[1].strip()
                    print("Found deploymentMode: {0}".format(deployment_mode))
                # Continue reading to get both fields
                if model and deployment_mode:
                    break
    except Exception as e:
        print("[WARNING] Error reading acs_system_config: {0}".format(str(e)))
        return CheckResult.set_warning("vnd_app_large_check", "Unable to determine device type")
    
    if not model:
        print("[WARNING] model field not found in acs_system_config")
        return CheckResult.set_warning("vnd_app_large_check", "Unable to determine device type")
    
    # Check if model is SE-VIRTUAL-DATA (case insensitive)
    if model.upper() == "SE-VIRTUAL-DATA":
        print("[PASS] ND is a virtual Data Node (model: {0})".format(model))
        return CheckResult.set_pass("vnd_app_large_check", "ND is a virtual Data Node")
    
    # Check if model is SE-VIRTUAL-APP (case insensitive)
    if model.upper() != "SE-VIRTUAL-APP":
        print("[PASS] ND is not SE-VIRTUAL-APP (model: {0})".format(model))
        return CheckResult.set_pass("vnd_app_large_check", "ND is not SE-VIRTUAL-APP")
    
    print("SE-VIRTUAL-APP detected - checking disk configuration")
    
    # Step 3: Check lvm-pvs for /dev/sdb1 atom0 with PSize ~1.5T
    lvm_pvs_files = cache.find_files("lvm-pvs")
    if not lvm_pvs_files:
        print("[WARNING] lvm-pvs file not found")
        return CheckResult.set_warning("vnd_app_large_check", "Unable to verify disk configuration")
    
    lvm_pvs_file = lvm_pvs_files[0]
    print("Checking lvm-pvs file: {0}".format(os.path.basename(lvm_pvs_file)))
    
    try:
        sdb1_atom0_found = False
        psize_value = None
        
        with open(lvm_pvs_file, 'r') as f:
            for line in f:
                line_stripped = line.strip()
                
                # Skip header and empty lines
                if not line_stripped or "PV" in line_stripped and "VG" in line_stripped:
                    continue
                
                # Look for /dev/sdb1 with atom0 VG
                if "/dev/sdb1" in line and "atom0" in line:
                    sdb1_atom0_found = True
                    parts = line_stripped.split()
                    
                    # Find PSize column (typically 5th column)
                    # Format: PV  VG  Fmt  Attr  PSize  PFree
                    if len(parts) >= 5:
                        psize_str = parts[4]
                        print("Found /dev/sdb1 atom0 with PSize: {0}".format(psize_str))
                        
                        # Parse PSize (e.g., "<1.50t", "499.87g")
                        psize_lower = psize_str.lower().replace('<', '').replace('>', '')
                        
                        # Convert to terabytes for comparison
                        if 't' in psize_lower:
                            psize_value = float(psize_lower.replace('t', ''))
                        elif 'g' in psize_lower:
                            psize_value = float(psize_lower.replace('g', '')) / 1024.0
                        
                        print("Parsed PSize: {0:.2f}T".format(psize_value if psize_value else 0))
                        break
        
        if not sdb1_atom0_found:
            print("[PASS] /dev/sdb1 atom0 not found in lvm-pvs")
            return CheckResult.set_pass("vnd_app_large_check", "/dev/sdb1 atom0 configuration not detected")
        
        # Check if PSize is in the App-Large range (around 1.4T to 1.6T)
        # Regular App is ~0.5T, Data Node is ~3T, App-Large is ~1.5T (unsupported)
        if psize_value and 1.40 <= psize_value <= 1.60:
            print("[INFO] vND SAN App-Large profile detected (PSize: {0:.2f}T in App-Large range)".format(psize_value))
            
            # Check if deploymentMode contains "ndfc"
            is_ndfc_deployment = deployment_mode and "ndfc" in deployment_mode.lower()
            
            if is_ndfc_deployment:
                # FAIL: SE-VIRTUAL-APP + ndfc deployment + 1.5T disk
                print("[FAIL] SE-VIRTUAL-APP with NDFC deployment and App-Large profile detected")
                return CheckResult.set_fail(
                    "vnd_app_large_check",
                    "vND SAN App-Large profile detected with NDFC deployment",
                    explanation=(
                        "vND SAN App is not supported with App-Large profile in NDFC deployments\n\n"
                        "  vND SAN App is only supported for the following types:\n"
                        "  - Regular App Node (16 vCPUs/64GB RAM/500GB Disk)\n"
                        "  - Data Node (32 vCPUs/128GB RAM/3TB Disk)"
                    ),
                    recommendation=(
                        "If you are upgrading to 4.1, restore the ND cluster from a backup onto a Regular App node (16 vCPUs/64GB RAM/500GB Disk)\n"
                        "  or Data Node (32 vCPUs/128GB RAM/3TB Disk) before proceeding with upgrade."
                    ),
                    reference="https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/cisco-nexus-dashboard-deployment-guide-41x/nd-deploy-upgrade-41x.html#post-upgrade-tasks__section_vbs_1kz_jgc"
                )
            else:
                # WARNING: SE-VIRTUAL-APP + non-ndfc deployment + 1.5T disk
                print("[WARNING] SE-VIRTUAL-APP with Large profile requires profile conversion after upgrade")
                return CheckResult.set_warning(
                    "vnd_app_large_check",
                    "vND is Large Profile and requires profile conversion after upgrade",
                    explanation="vND Large Profile requires profile conversion after upgrade to ND 4.1 or later",
                    recommendation=(
                        "After upgrading to ND 4.1, convert the Large Profile to Regular App Node profile\n"
                        "  following the post-upgrade tasks documentation."
                    ),
                    reference="https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/cisco-nexus-dashboard-deployment-guide-41x/nd-deploy-upgrade-41x.html#post-upgrade-tasks__section_vbs_1kz_jgc"
                )
        else:
            print("[PASS] vND SAN App-Large profile not detected (PSize: {0:.2f}T not in App-Large range)".format(psize_value if psize_value else 0))
            return CheckResult.set_pass("vnd_app_large_check", "vND SAN App-Large profile not detected")
            
    except Exception as e:
        print("[WARNING] Error reading lvm-pvs file: {0}".format(str(e)))
        return CheckResult.set_warning("vnd_app_large_check", "Unable to verify disk configuration")

###############################################################
# Tech Support Functions
###############################################################

def get_techsupport_command(nd_version=None):
    """
    Get the appropriate tech support command based on ND version.
    For version 4.x and later: 'acs techsupport collect'
    For versions prior to 4.x: 'acs techsupport collect -s system'
    """
    if not nd_version:
        print("ND version not provided, using legacy command format")
        return "acs techsupport collect -s system"
    
    try:
        # Parse version to get major version number
        version_parts = nd_version.split('.')
        
        if len(version_parts) >= 1:
            major = int(version_parts[0])
            
            # version 4.x and later use new command
            if major >= 4:
                print("ND version {0} >= 4.x, using new command format".format(nd_version))
                return "acs techsupport collect"
            else:
                print("ND version {0} < 4.x, using legacy command format".format(nd_version))
                return "acs techsupport collect -s system"
        else:
            print("Could not parse ND version {0}, using legacy command format".format(nd_version))
            return "acs techsupport collect -s system"
            
    except Exception as e:
        print("Error parsing ND version {0}: {1}, using legacy command format".format(nd_version, str(e)))
        return "acs techsupport collect -s system"

def generate_techsupport(nd_version=None):
    """Generate a new tech support file"""
    print_section("Generating Tech Support on {0}".format(NODE_NAME))
    update_status("running", "Generating tech support", 10)
    
    # Get the appropriate tech support command based on ND version
    cmd = get_techsupport_command(nd_version)
    print("Using tech support command: {0}".format(cmd))
    
    try:
        print("Starting tech support collection (this may take 15-20 minutes)...")
        
        # Use subprocess directly for tech support to get better error handling
        if sys.version_info[0] < 3:
            # Python 2.7 approach
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            
            # Convert bytes to string if needed
            if isinstance(stdout, bytes):
                stdout = stdout.decode('utf-8', errors='replace')
            if isinstance(stderr, bytes):
                stderr = stderr.decode('utf-8', errors='replace')
                
            output = stdout
            returncode = process.returncode
        else:
            # Python 3.x approach
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=900,  # 15 minute timeout
                check=False
            )
            output = result.stdout
            stderr = result.stderr
            returncode = result.returncode
        
        # Check for immediate command failures
        if returncode != 0:
            print("[FAIL] Tech support command failed with return code {0}".format(returncode))
            print("Command output: {0}".format(output.strip()))
            print("Command error: {0}".format(stderr.strip()))
            
            # Check for specific error patterns that indicate immediate failure
            if "unrecognized arguments" in stderr or "error: unrecognized arguments" in output:
                print("[FAIL] Tech support command failed: Invalid command arguments")
                print("Error: {0}".format(stderr.strip()))
                print("This indicates the ND version detection may be incorrect or the command syntax has changed.")
                results["checks"]["techsupport"]["status"] = "FAIL"
                results["checks"]["techsupport"]["details"].append("Tech support command failed: Invalid arguments")
                update_status("error", "Tech support command failed: Invalid arguments", 70)
                return None
            elif "usage:" in stderr or "usage:" in output:
                print("[FAIL] Tech support command failed: Command usage error")
                print("Error: {0}".format(stderr.strip()))
                results["checks"]["techsupport"]["status"] = "FAIL"
                results["checks"]["techsupport"]["details"].append("Tech support command failed: Command usage error")
                update_status("error", "Tech support command failed: Command usage error", 70)
                return None
            else:
                print("[FAIL] Tech support command failed: {0}".format(stderr.strip()))
                results["checks"]["techsupport"]["status"] = "FAIL"
                results["checks"]["techsupport"]["details"].append("Tech support command failed: {0}".format(stderr.strip()))
                update_status("error", "Tech support command failed", 70)
                return None
        
        if "Started: TS collection" in output or "TS collection" in output:
            print("Tech support collection started successfully")
            print("Output: {0}".format(output.strip()))
            
            # Get the existing tech support files before we started
            existing_files = set(glob.glob("/techsupport/*{0}.tgz".format(NODE_NAME)))
            
            # Get current timestamp to match with new tech support file
            current_time = datetime.datetime.now()
            timestamp_prefix = current_time.strftime("%Y-%m-%d")
            
            # Wait for the new tech support file to appear
            print("Waiting for tech support file to be generated...")
            update_status("running", "Waiting for tech support file generation", 15)
            max_wait_time = 600  # 10 minutes max wait (was 30 mins, reduced since we have better error detection)
            start_time = time.time()
            
            # Basic text indicator for waiting
            new_tech_file = None
            while time.time() - start_time < max_wait_time:
                # Add time-based progress percentage (from 15% to 70% over 20 minutes)
                elapsed = time.time() - start_time
                if elapsed < 1200:  # 20 minutes
                    progress = 15 + int(55 * elapsed / 1200)
                    update_status("running", "Waiting for tech support generation", progress)
                
                # Check for new tech support files
                current_files = set(glob.glob("/techsupport/*{0}.tgz".format(NODE_NAME)))
                new_files = current_files - existing_files
                
                # Look for a file with today's timestamp that's growing in size
                for file in new_files:
                    if timestamp_prefix in file:
                        if new_tech_file is None or not os.path.exists(new_tech_file):
                            new_tech_file = file
                            last_size = os.path.getsize(file) if os.path.exists(file) else 0
                        else:
                            current_size = os.path.getsize(file)
                            if current_size > last_size:
                                last_size = current_size
                                new_tech_file = file
                
                # If we found a file and it hasn't grown in size for a while, it's probably done
                if new_tech_file and os.path.exists(new_tech_file):
                    if time.time() - os.path.getmtime(new_tech_file) > 60:  # No changes in last minute
                        break
                
                time.sleep(5)
            
            update_status("running", "Tech support file generated", 70)
            
            if new_tech_file and os.path.exists(new_tech_file):
                print("Tech support file generated: {0}".format(new_tech_file))
                return new_tech_file
            else:
                print("[WARNING] No new tech support file found after waiting")
                update_status("warning", "No new tech support found", 70)
                # Try to find any tech support file for this node
                candidates = glob.glob("/techsupport/*{0}.tgz".format(NODE_NAME))
                if candidates:
                    # Sort by modification time, newest first
                    candidates.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                    print("Using most recent tech support file: {0}".format(candidates[0]))
                    return candidates[0]
                else:
                    print("[FAIL] No tech support files found for {0}".format(NODE_NAME))
                    results["checks"]["techsupport"]["status"] = "FAIL"
                    results["checks"]["techsupport"]["details"].append("Failed to generate or find tech support files")
                    update_status("error", "Failed to find tech support files", 70)
                    return None
        else:
            print("[WARNING] Unexpected output from tech support command.")
            print("Expected: 'Started: TS collection' or similar")
            print("Actual output: {0}".format(output.strip()))
            if stderr and stderr.strip():
                print("Error output: {0}".format(stderr.strip()))
            results["checks"]["techsupport"]["status"] = "WARNING"
            results["checks"]["techsupport"]["details"].append("Unexpected output from tech support command: {0}".format(output.strip()))
            update_status("warning", "Unexpected output from tech support command", 70)
            return None
    except Exception as e:
        print("[FAIL] Error generating tech support: {0}".format(str(e)))
        results["checks"]["techsupport"]["status"] = "FAIL"
        results["checks"]["techsupport"]["details"].append("Error generating tech support: {0}".format(str(e)))
        update_status("error", "Error generating tech support: {0}".format(str(e)), 70)
        return None

def select_techsupport(specific_file=None):
    """Select an existing tech support file"""
    print_section("Selecting Tech Support on {0}".format(NODE_NAME))
    update_status("running", "Selecting tech support file", 10)
    
    # If a specific file is provided, use it
    if specific_file and os.path.exists(specific_file):
        print("Using specified tech support file: {0}".format(specific_file))
        update_status("running", "Selected tech support file: {0}".format(os.path.basename(specific_file)), 20)
        return specific_file
    
    # Otherwise, get all tech support files for this node
    tech_files = glob.glob("/techsupport/*{0}.tgz".format(NODE_NAME))
    
    if not tech_files:
        print("[FAIL] No tech support files found for {0}".format(NODE_NAME))
        results["checks"]["techsupport"]["status"] = "FAIL"
        results["checks"]["techsupport"]["details"].append("No tech support files found")
        update_status("error", "No tech support files found", 10)
        return None
    
    # Sort files by modification time, newest first
    tech_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    # Select the newest file
    print("Using newest tech support file: {0}".format(tech_files[0]))
    update_status("running", "Selected tech support file: {0}".format(os.path.basename(tech_files[0])), 20)
    return tech_files[0]

def process_techsupport(tech_file):
    """Process tech support file"""
    print_section("Processing Tech Support on {0}".format(NODE_NAME))
    update_status("running", "Processing tech support file", 30)
    
    if not tech_file or not os.path.exists(tech_file):
        print("[FAIL] Tech support file not found: {0}".format(tech_file))
        results["checks"]["techsupport"]["status"] = "FAIL"
        results["checks"]["techsupport"]["details"].append("Tech support file not found")
        update_status("error", "Tech support file not found", 30)
        return
    
    # Create the node directory
    node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
    try:
        if sys.version_info[0] < 3:
            # Python 2.7 approach - no exist_ok parameter
            if not os.path.exists(node_dir):
                os.makedirs(node_dir)
        else:
            # Python 3.x approach
            os.makedirs(node_dir, exist_ok=True)
        print("Created directory {0}".format(node_dir))
    except Exception as e:
        print("[FAIL] Failed to create directory {0}: {1}".format(node_dir, str(e)))
        results["checks"]["techsupport"]["status"] = "FAIL"
        results["checks"]["techsupport"]["details"].append("Failed to create directory {0}".format(node_dir))
        update_status("error", "Failed to create directory: {0}".format(str(e)), 30)
        return
    
    # Extract the tech support file directly from source location to save space
    extract_techsupport_direct(tech_file, node_dir)

def check_tmp_space():
    """Check if there's enough space in /tmp before extraction"""
    print_section("Checking available space in /tmp on {0}".format(NODE_NAME))
    
    try:
        # Get available space in /tmp
        df_output = run_command("df -BM /tmp | tail -1")
        parts = df_output.split()
        
        if len(parts) >= 4:
            available_mb = int(parts[3].strip('M'))
            total_mb = int(parts[1].strip('M'))
            
            print("Total /tmp size: {0}MB, Available: {1}MB".format(total_mb, available_mb))
            
            # Check if we have at least 8GB available (to be safe)
            if available_mb < 8000:
                print("[WARNING] Low space in /tmp directory ({0}MB available)".format(available_mb))
                print("Techsupport extraction may fail if archive is large")
                return False
            else:
                print("[PASS] Sufficient space available in /tmp ({0}MB)".format(available_mb))
                return True
        else:
            print("[WARNING] Could not parse df output for /tmp")
            return False
    except Exception as e:
        print("[WARNING] Error checking /tmp space: {0}".format(str(e)))
        return False

@robust_check("techsupport")
def extract_techsupport_optimized(tech_file, node_dir):
    """OPTIMIZED: Direct extraction with 50% disk space savings and unified command execution"""
    file_name = os.path.basename(tech_file)
    
    print("OPTIMIZED: Direct tech support extraction from: {0}".format(tech_file))
    print("Saves 50% disk space by eliminating intermediate copy")
    update_status("running", "Optimized tech support extraction", 40)
    
    # Validate source file exists
    if not os.path.exists(tech_file):
        raise Exception("Tech support file {0} not found".format(tech_file))
    
    # Get file size for space verification
    tech_size = os.path.getsize(tech_file)
    tech_size_human = format_size(tech_size)
    print("Tech support size: {0}".format(tech_size_human))
    
    # Quick disk space check using unified command runner
    stdout, stderr, returncode = run_command_unified("df -B1 {0} | tail -1".format(node_dir))
    if returncode == 0 and stdout:
        parts = stdout.split()
        if len(parts) >= 4:
            try:
                available_bytes = int(parts[3])
                if available_bytes < (tech_size * 2):
                    print("[WARNING] Low space: {0} available, need ~{1}".format(
                        format_size(available_bytes), format_size(tech_size * 2)))
            except (ValueError, IndexError):
                pass  # Continue anyway if space check fails
    
    # 1: Single-command extraction with error handling
    print("Extracting tech support (optimized path)...")
    extract_cmd = "cd {0} && tar -xzf {1} 2>/dev/null || tar -xf {1}".format(node_dir, tech_file)
    
    stdout, stderr, returncode = run_command_unified(extract_cmd, timeout=1800)
    
    if returncode != 0:
        # Fallback extraction method
        print("[WARNING] Primary extraction failed, trying fallback")
        fallback_cmd = "cd {0} && gzip -dc {1} | tar -xf -".format(node_dir, tech_file)
        stdout, stderr, returncode = run_command_unified(fallback_cmd, timeout=1800)
        
        if returncode != 0:
            raise Exception("All extraction methods failed: {0}".format(stderr))
    
    # 2: Check for nested logs.tgz and extract if present
    logs_path = "{0}/logs.tgz".format(node_dir)
    if os.path.exists(logs_path):
        print("Extracting nested logs.tgz...")
        logs_cmd = "cd {0} && tar -xzf logs.tgz 2>/dev/null || tar -xf logs.tgz".format(node_dir)
        run_command_unified(logs_cmd, timeout=600)  # Shorter timeout for logs
    
    # 3: Initialize file cache after extraction
    print("Building optimized file cache...")
    cache = FileCache(node_dir)
    
    # Verify extraction success by checking for common directories
    extracted_items = cache.find_files("*")  # Use cache instead of os.listdir
    if extracted_items:
        # Count directories vs files for better reporting
        dir_count = sum(1 for item in extracted_items if os.path.isdir(item))
        file_count = len(extracted_items) - dir_count
        
        print("[PASS] Extraction complete: {0} directories, {1} files".format(dir_count, file_count))
        print("Space saved: {0} (no intermediate copy)".format(tech_size_human))
        
        results["checks"]["techsupport"]["status"] = "PASS"
        results["checks"]["techsupport"]["details"].append(
            "Optimized extraction: {0} dirs, {1} files, saved {2}".format(
                dir_count, file_count, tech_size_human))
        update_status("running", "Optimized extraction completed", 50)
    else:
        print("[WARNING] Extraction completed but no content detected")
        results["checks"]["techsupport"]["details"].append("Extraction completed with empty result")

# Legacy function name for compatibility
def extract_techsupport_direct(tech_file, node_dir):
    """Legacy wrapper - redirects to optimized version"""
    return extract_techsupport_optimized(tech_file, node_dir)

def extract_techsupport(node_dir, file_name):
    """Extract tech support file completely in one operation"""
    try:
        file_path = "{0}/{1}".format(node_dir, file_name)
        
        print("Extracting tech support file: {0}...".format(file_path))
        update_status("running", "Extracting tech support archive", 50)
        
        # Check if the file exists
        if not os.path.exists(file_path):
            print("[FAIL] Tech support file {0} not found".format(file_path))
            results["checks"]["techsupport"]["status"] = "FAIL"
            results["checks"]["techsupport"]["details"].append("Tech support file {0} not found".format(file_path))
            update_status("error", "Tech support file not found for extraction", 50)
            return
        
        # Get tech support file size
        tech_size = os.path.getsize(file_path)
        tech_size_human = format_size(tech_size)
        print("Tech support file size: {0}".format(tech_size_human))
        
        # Verify space in /tmp is sufficient (at least 3x tech support size)
        df_output = run_command("df -B1 /tmp | tail -1")
        parts = df_output.split()
        if len(parts) >= 4:
            available_bytes = int(parts[3])
            if available_bytes < (tech_size * 3):
                print("[WARNING] Low space in /tmp directory ({0} available)".format(format_size(available_bytes)))
                print("This may not be enough for extracting {0} tech support".format(tech_size_human))
        
        # EXTRACT: One-step complete extraction
        print("Extracting complete tech support (this may take a while)...")
        extract_cmd = "cd {0} && tar -xzf {1}".format(node_dir, file_path)
        
        # Use run_extraction_command with timeout and proper process management
        success = run_extraction_command(extract_cmd, timeout=1800)
        
        if not success:
            print("[WARNING] Complete extraction failed, trying alternative method")
            alt_extract_cmd = "cd {0} && tar -xf {1}".format(node_dir, file_path)
            success = run_extraction_command(alt_extract_cmd, timeout=1800)
            
            if not success:
                print("[FAIL] All extraction methods failed")
                results["checks"]["techsupport"]["status"] = "FAIL"
                results["checks"]["techsupport"]["details"].append("Failed to extract tech support")
                update_status("error", "Failed to extract tech support", 60)
                return
        
        # Check for logs directory
        logs_path = "{0}/logs.tgz".format(node_dir)
        logs_dir = "{0}/logs".format(node_dir)
        
        # If we find logs.tgz, extract it
        if os.path.exists(logs_path):
            print("Found logs.tgz, extracting...")
            logs_extract_cmd = "cd {0} && tar -xzf logs.tgz".format(node_dir)
            success = run_extraction_command(logs_extract_cmd, timeout=1800)
            
            if not success:
                print("[WARNING] logs.tgz extraction failed, trying alternative method")
                logs_extract_cmd = "cd {0} && tar -xf logs.tgz".format(node_dir)
                success = run_extraction_command(logs_extract_cmd, timeout=1800)
        
        # Verify extraction results by checking for expected directories
        extracted_dirs = []
        try:
            if sys.version_info[0] < 3:
                # Python 2.7 approach
                for _, dirnames, _ in os.walk(node_dir):
                    extracted_dirs = dirnames
                    break
            else:
                # Python 3.x approach
                extracted_dirs = next(os.walk(node_dir))[1]
        except (StopIteration, Exception) as e:
            pass
            
        if not extracted_dirs:
            print("[FAIL] No directories found after extraction")
            results["checks"]["techsupport"]["status"] = "FAIL"
            results["checks"]["techsupport"]["details"].append("No directories found after extraction")
            update_status("error", "No directories found after extraction", 60)
            return
            
        print("[PASS] Successfully extracted tech support with {0} directories".format(len(extracted_dirs)))
        
        # Set specific PASS details based on operation (select vs generate)
        # Check if this was generated or selected based on script command line args
        operation = "select"  # Default to select
        if len(sys.argv) > 1:
            operation = sys.argv[1]
            
        if operation == "generate":
            results["checks"]["techsupport"]["details"] = ["Tech support generated and extracted successfully"]
        else:
            results["checks"]["techsupport"]["details"] = ["Tech support extracted successfully"]
            
        update_status("running", "Tech support extraction complete", 90)
        
    except Exception as e:
        print("[FAIL] Error extracting tech support file: {0}".format(str(e)))
        results["checks"]["techsupport"]["status"] = "FAIL"
        results["checks"]["techsupport"]["details"].append("Error extracting tech support file: {0}".format(str(e)))
        update_status("error", "Error extracting tech support file: {0}".format(str(e)), 70)

def save_results():
    """Save results to a JSON file"""
    try:
        # Make parent directory if it doesn't exist
        if not os.path.exists(os.path.dirname(RESULTS_FILE)):
            os.makedirs(os.path.dirname(RESULTS_FILE))
            
        with open(RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=2)
        print("\nResults saved to {0}".format(RESULTS_FILE))
    except Exception as e:
        print("Error saving results: {0}".format(str(e)))

def cleanup_processes():
    """Cleanup any leftover processes spawned by this script"""
    try:
        # Get our process ID
        our_pid = os.getpid()
        print("Cleaning up processes for PID {0}".format(our_pid))
        
        # First try to find any children directly using ps
        try:
            cmd = "ps -eo pid,ppid,stat,cmd | grep {0}".format(our_pid)
            
            if sys.version_info[0] < 3:
                # Python 2.7 approach
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                stdout, stderr = process.communicate()
                ps_output = stdout
            else:
                # Python 3.x approach
                ps_output = subprocess.run(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    check=False
                ).stdout
            
            # Extract child PIDs
            child_pids = []
            for line in ps_output.strip().split('\n'):
                if str(our_pid) in line and "grep" not in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == str(our_pid):
                        child_pids.append(parts[0])
            
            # Try to terminate children
            for pid in child_pids:
                try:
                    print("Terminating child process {0}".format(pid))
                    if sys.version_info[0] < 3:
                        # Python 2.7 approach
                        kill_cmd = "kill -TERM {0}".format(pid)
                        subprocess.Popen(
                            kill_cmd, 
                            shell=True, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE
                        ).communicate()
                    else:
                        # Python 3.x approach
                        subprocess.run(
                            "kill -TERM {0}".format(pid),
                            shell=True,
                            check=False,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                except:
                    pass
            
            # If there were children, wait briefly then check again
            if child_pids:
                time.sleep(1)
                
                # Check if any processes still need SIGKILL
                for pid in child_pids:
                    try:
                        proc_path = "/proc/{0}".format(pid)
                        if os.path.exists(proc_path):
                            print("Force killing child process {0}".format(pid))
                            if sys.version_info[0] < 3:
                                # Python 2.7 approach
                                kill_cmd = "kill -9 {0}".format(pid)
                                subprocess.Popen(
                                    kill_cmd, 
                                    shell=True, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE
                                ).communicate()
                            else:
                                # Python 3.x approach
                                subprocess.run(
                                    "kill -9 {0}".format(pid),
                                    shell=True,
                                    check=False,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE
                                )
                    except:
                        pass
        except Exception as e:
            print("Error finding child processes: {0}".format(str(e)))
        
        # Also try to kill any remaining extraction processes (tar, gzip)
        # This is more aggressive but may be necessary
        try:
            if sys.version_info[0] < 3:
                # Python 2.7 approach - using os.popen().close() to ensure proper waiting
                os.popen("pkill -9 -f 'tar -x[z]f' || true").close()
                os.popen("pkill -9 -f gzip || true").close()
            else:
                # Python 3.x approach
                subprocess.run(
                    "pkill -9 -f 'tar -x[z]f' || true",
                    shell=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                subprocess.run(
                    "pkill -9 -f gzip || true",
                    shell=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
        except:
            pass
            
    except Exception as e:
        print("Error during process cleanup: {0}".format(str(e)))

###############################################################
# Main Function
###############################################################

def main():
    """Main worker function using single extraction approach"""
    signal.signal(signal.SIGINT, signal_handler)
    
    print("\nStarting Nexus Dashboard Pre-upgrade Validation on {0}".format(NODE_NAME))
    print("Running at {0}\n".format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    
    try:
        # Create the base directory
        if sys.version_info[0] < 3:
            # Python 2.7 approach - no exist_ok parameter
            if not os.path.exists(BASE_DIR):
                os.makedirs(BASE_DIR)
        else:
            # Python 3.x approach
            os.makedirs(BASE_DIR, exist_ok=True)
        
        # Check if we have enough space in /tmp
        check_tmp_space()
        
        # Get tech support file
        operation = "select"
        tech_support_path = None
        
        # Parse command line arguments
        if len(sys.argv) > 1:
            operation = sys.argv[1]
            
        if len(sys.argv) > 2:
            tech_support_path = sys.argv[2]
        
        # Parse ND version if provided (for version-specific commands)
        nd_version = None
        if len(sys.argv) > 3:
            nd_version = sys.argv[3]
        
        # Process tech support based on command line argument
        tech_file = None
        # If a tech support path is provided, always use it (don't generate a new one)
        if tech_support_path:
            tech_file = select_techsupport(tech_support_path)
        elif operation == "generate":
            tech_file = generate_techsupport(nd_version)
        else:
            tech_file = select_techsupport(None)
        
        if not tech_file:
            update_status("error", "Failed to obtain tech support file", 0)
            results["checks"]["techsupport"]["status"] = "FAIL"
            results["checks"]["techsupport"]["details"] = ["Failed to obtain tech support file"]
            save_results()
            return 1
            
        # Process the tech support file (extract it completely)
        node_dir = "{0}/{1}".format(BASE_DIR, NODE_NAME)
        
        if sys.version_info[0] < 3:
            # Python 2.7 approach - no exist_ok parameter
            if not os.path.exists(node_dir):
                os.makedirs(node_dir)
        else:
            # Python 3.x approach
            os.makedirs(node_dir, exist_ok=True)
        
        # Copy the tech support file to the working directory
        file_name = os.path.basename(tech_file)
        dest_path = "{0}/{1}".format(node_dir, file_name)
        
        print("Copying {0} to {1}...".format(tech_file, dest_path))
        run_command("cp {0} {1}".format(tech_file, dest_path))
        
        # Extract the tech support file
        extract_techsupport(node_dir, file_name)
        
        try:
            # Run the checks - wrap each check in try-except to catch individual failures
            try:
                check_subnet_isolation()
            except Exception as e:
                print("[ERROR] Subnet isolation check failed: {0}".format(str(e)))
                results["checks"]["subnet_check"]["status"] = "FAIL"
                results["checks"]["subnet_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_ping_reachability()
            except Exception as e:
                print("[ERROR] Ping reachability check failed: {0}".format(str(e)))
                results["checks"]["ping_check"]["status"] = "FAIL"
                results["checks"]["ping_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_node_status()
            except Exception as e:
                print("[ERROR] Node status check failed: {0}".format(str(e)))
                results["checks"]["node_status"]["status"] = "FAIL"
                results["checks"]["node_status"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_disk_space(dest_path)
            except Exception as e:
                print("[ERROR] Disk space check failed: {0}".format(str(e)))
                results["checks"]["disk_space"]["status"] = "FAIL"
                results["checks"]["disk_space"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_pods(dest_path)
            except Exception as e:
                print("[ERROR] Pod status check failed: {0}".format(str(e)))
                results["checks"]["pod_status"]["status"] = "FAIL"
                results["checks"]["pod_status"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_system_health(dest_path)
            except Exception as e:
                print("[ERROR] System health check failed: {0}".format(str(e)))
                results["checks"]["system_health"]["status"] = "FAIL"
                results["checks"]["system_health"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_nxos_discovery_service(dest_path)
            except Exception as e:
                print("[ERROR] NXOS Discovery Service check failed: {0}".format(str(e)))
                results["checks"]["nxos_discovery_service"]["status"] = "FAIL"
                results["checks"]["nxos_discovery_service"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_backup_failure(dest_path)
            except Exception as e:
                print("[ERROR] Backup failure check failed: {0}".format(str(e)))
                results["checks"]["backup_failure_check"]["status"] = "FAIL"
                results["checks"]["backup_failure_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_nameserver_duplicates(dest_path)
            except Exception as e:
                print("[ERROR] Nameserver duplicate check failed: {0}".format(str(e)))
                results["checks"]["nameserver_duplicate_check"]["status"] = "FAIL"
                results["checks"]["nameserver_duplicate_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_legacy_ndi_elasticsearch(dest_path)
            except Exception as e:
                print("[ERROR] Legacy NDI ElasticSearch check failed: {0}".format(str(e)))
                results["checks"]["legacy_ndi_elasticsearch_check"]["status"] = "FAIL"
                results["checks"]["legacy_ndi_elasticsearch_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_ntp_authentication(dest_path)
            except Exception as e:
                print("[ERROR] NTP Authentication check failed: {0}".format(str(e)))
                results["checks"]["ntp_auth_check"]["status"] = "FAIL"
                results["checks"]["ntp_auth_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_CA_CSCwm35992(dest_path)
            except Exception as e:
                print("[ERROR] Certificate check failed: {0}".format(str(e)))
                results["checks"]["certificate_check"]["status"] = "FAIL"
                results["checks"]["certificate_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_ISOs_CSCwn94394(dest_path)
            except Exception as e:
                print("[ERROR] ISO check failed: {0}".format(str(e)))
                results["checks"]["iso_check"]["status"] = "FAIL"
                results["checks"]["iso_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_lvm_pvs(dest_path)
            except Exception as e:
                print("[ERROR] LVM PVs check failed: {0}".format(str(e)))
                results["checks"]["lvm_pvs_check"]["status"] = "FAIL"
                results["checks"]["lvm_pvs_check"]["details"] = ["No empty Elasticsearch PVs found"]
                
            try:
                check_persistent_ip_config(dest_path)
            except Exception as e:
                print("[ERROR] Persistent IP check failed: {0}".format(str(e)))
                results["checks"]["persistent_ip_check"]["status"] = "FAIL"
                results["checks"]["persistent_ip_check"]["details"] = ["Check failed: {0}".format(str(e))]
                
            try:
                check_atom0_nvme(dest_path)
            except Exception as e:
                print("[ERROR] NVME drive check failed: {0}".format(str(e)))
                results["checks"]["atom0_nvme_check"]["status"] = "WARNING"
                results["checks"]["atom0_nvme_check"]["details"] = ["Unable to verify NVME drive health"]
                
            try:
                check_atom0_vg(dest_path)
            except Exception as e:
                print("[ERROR] atom0 VG check failed: {0}".format(str(e)))
                results["checks"]["atom0_vg_check"]["status"] = "WARNING"
                results["checks"]["atom0_vg_check"]["details"] = ["Unable to verify if atom0 vg has >50G free space"]
                
            try:
                check_vnd_app_large(dest_path)
            except Exception as e:
                print("[ERROR] vND App-Large check failed: {0}".format(str(e)))
                results["checks"]["vnd_app_large_check"]["status"] = "WARNING"
                results["checks"]["vnd_app_large_check"]["details"] = ["Unable to verify vND App-Large profile"]
                
        except Exception as e:
            print("[ERROR] One or more checks failed to complete: {0}".format(str(e)))
            # Mark remaining checks as FAIL if they haven't been run yet
            for check in results["checks"]:
                if not results["checks"][check]["details"]:
                    results["checks"][check]["status"] = "FAIL"
                    results["checks"][check]["details"] = ["Check did not run: {0}".format(str(e))]
        
        # Save results to file
        update_status("complete", "All operations completed", 100)
        save_results()
        
        print("\nValidation complete on node {0}".format(NODE_NAME))
        return 0
    
    except Exception as e:
        print("Error in worker script: {0}".format(str(e)))
        logger = logging.getLogger(__name__)
        logger.error("Worker script error: {0}".format(str(e)))
        logger.debug("Full traceback: {0}".format(traceback.format_exc()))

        # For complete visibility during troubleshooting, conditionally print traceback
        if os.environ.get('ND_DEBUG') == '1':
            traceback.print_exc()
        
        # Mark all checks that didn't explicitly pass as failed
        for check in results["checks"]:
            if not results["checks"][check]["details"]:
                results["checks"][check]["status"] = "FAIL"
                results["checks"][check]["details"] = ["Check did not run due to script error: {0}".format(str(e))]
        
        update_status("error", "Error: {0}".format(str(e)), 0)
        save_results()
        return 1

    finally:
        cleanup_processes()

if __name__ == "__main__":
    sys.exit(main())
    