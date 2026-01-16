# ND-Pre-Upgrade-Validation-Script

The script checks for issues that are known to have an impact to the success of a Nexus Dashboard upgrade. Identification and remediation of such issues prior to upgrade can lead to more successful outcomes.

The script can be run from any Linux server with the required dependencies. If ACI APICs are available and have connectivity towards the ND management address, the script can be run from an APIC as these devices already contain all dependencies required to run the script. The script **cannot** be run from the Nexus Dashboard itself.

- The script can be run against any ND versions starting from Version 2.1.
- Due to a /tmp permissions discrepancy, running the script on 4.1.1g requires root access.
- If you have feedback or are encountering an issue running the script, please send an email to nd-preupgrade-validation@cisco.com

<video src="https://github.com/user-attachments/assets/0bcbc1f0-98c0-4e8f-8cfe-20265f52779e" controls></video>

## Table of Contents

- [Checks](#checks)
- [Dependencies and Installation](#dependencies-and-installation)
  - [Python Requirements](#python-requirements)
  - [Installing Dependencies](#installing-dependencies)
  - [Dependencies Overview](#dependencies-overview)
- [Usage](#usage)
  - [Compatibility Notes](#compatibility-notes)
  - [Example Run](#example-run)
- [Support](#support)

## Checks

**Note:** Some of the checks are version specific and might not apply to the current running version of Nexus Dashboard in your environment. In the event that the check is not relevant, the check will be a "PASS".

| # | Check | Description | Reference |
|---|-------|-------------|-----------|
| 1 | Techsupport | Verify the script could successfully extract the tech support to perform additional checks | |
| 2 | Version | Verify all cluster nodes are running the same version | |
| 3 | Node status | Verify all cluster nodes are in an Active state | |
| 4 | Ping check | Verify node can ping all Mgmt and Data IPs in the cluster | |
| 5 | Subnet check | Verify Mgmt and Data interfaces are on different subnets | [Documentation](https://www.cisco.com/c/en/us/td/docs/dcn/nd/3x/deployment/cisco-nexus-dashboard-and-services-deployment-guide-311/nd-prerequisites-platform-31x.html#concept_fdf_fxg_4mb) |
| 6 | Persistent IP check | Verify at lest 5 Persistent IP address are configured in data-external-services | [Documentation](https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/cisco-nexus-dashboard-deployment-guide-41x/nd-prerequisites-41x.html#concept_zkj_3hj_cgc) |
| 7 | Disk space | Verify all directories are under 70% utilization | |
| 8 | Pod status | Verify all Pods and Services are in a healthy state | |
| 9 | System health | Verify all nodes are healthy using 'acs health' command | |
| 10 | NXOS Discovery Service | Verify cisco-ndfc k8 App is not stuck in Disabling | [CSCwm97680](https://bst.cisco.com/bugsearch/bug/CSCwm97680) |
| 11 | Backup failure check | Verify latest backup is not in Failed or InProgress state | [CSCwq57968](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwq57968), [CSCwm96512](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm96512) |
| 12 | Nameserver duplicate check | Verify no duplicate nameservers exist in acs_system_config | |
| 13 | Legacy NDI ElasticSearch | Verify legacy NDI ElasticSearch LV does not exist for non-NDI deployments | [CSCwr43810](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwr43810) |
| 14 | NTP authentication check | Verify no NTP servers have authentication enabled | [CSCwr97181](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwr97181) |
| 15 | Certificate check | Verify no certificates have non-alphanumeric characters | [CSCwm35992](https://bst.cisco.com/bugsearch/bug/CSCwm35992) |
| 16 | ISO check | Verify multiple ISOs aren't found in boothook | [CSCwn94394](https://bst.cisco.com/bugsearch/bug/CSCwn94394) |
| 17 | Lvm Pvs check | Verify no empty ElasticSearch PVs are found | [CSCwe91228](https://bst.cisco.com/bugsearch/bug/CSCwe91228) |
| 18 | atom0 NVME check | Verify no NVME drive hardware failures are present in Physical node setups | |
| 19 | atom0 vg check | Verify there is more than 50% free space in atom0 virtual group | [CSCwr43515](https://bst.cisco.com/bugsearch/bug/CSCwr43515) |
| 20 | vND App Large check | Verify vND SE-VIRTUAL-APP is not using Large Profile | [CSCws77374](https://bst.cisco.com/bugsearch/bug/CSCws77374), [Documentation](https://www.cisco.com/c/en/us/td/docs/dcn/nd/3x/deployment/cisco-nexus-dashboard-and-services-deployment-guide-321/nd-deploy-esx-32x.html#concept_zkv_y2g_mmb) |

## Dependencies and Installation

### Python Requirements
The main script requires Python 3.7+ while the worker script is compatible with Python 2.7+ to accommodate older ND node versions.

### Installing Dependencies
Most dependencies are part of Python's standard library. For the few external dependencies:

1. **Install Python dependencies using pip:**
   ```bash
   pip install -r requirements.txt
   ```
   
   Or for Python 3 specifically:
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Install system dependencies:**
   - **Linux/Unix:** Install `sshpass` for SSH authentication:
     ```bash
     sudo apt-get update
     sudo apt-get install sshpass
     ```
   - **macOS:** Use Homebrew:
     ```bash
     brew install hudochenkov/sshpass/sshpass
     ```
   - **Windows:** Consider using WSL (Windows Subsystem for Linux) for best compatibility

### Dependencies Overview
- **ipaddr/ipaddress**: For IP address validation and manipulation
  - `ipaddr` package for Python 2.7 (worker script on older ND nodes)
  - Built-in `ipaddress` module for Python 3+ (main script and newer ND nodes)
- **sshpass**: External system tool for password-based SSH authentication
- All other dependencies are part of Python's standard library

## Usage

Place the main script `ND-Preupgrade-Validation.py` and the worker script `worker_functions.py` in the same directory and execute the main script with the command `python ND-Preupgrade-Validation.py` or `python3 ND-Preupgrade-Validation.py`

### Compatibility Notes
- The main script is currently only compatible with Python 3.7+ but will be modified in the future.
- The worker script is Python 2.7+ compatible to accommodate ND nodes on versions prior to 3.0.

### Example Run:
```
[root@localhost preupgrade]# python3 ND-Preupgrade-Validation.py
Nexus Dashboard Pre-upgrade Validation Script
Running validation checks on 2026-01-16 11:13:58
Enter Nexus Dashboard IP address: 14.2.29.130
Enter password for rescue-user:

Connecting to Nexus Dashboard at 14.2.29.130...
Successfully connected to Nexus Dashboard at 14.2.29.130
Nexus Dashboard version: 3.2.2f
Discovering Nexus Dashboard nodes...
Found 3 Nexus Dashboard nodes
---------------------------------------
        ND1 (14.2.29.130)
        ND2 (14.2.29.131)
        ND3 (14.2.29.132)
---------------------------------------

Checking disk space on all nodes...
Checking ND1... PASS
Checking ND2... PASS
Checking ND3... PASS

Checking for large eventmonitoring log files...
Checking ND1... PASS
Checking ND2... PASS
Checking ND3... PASS

PASS All 3 nodes are active and have healthy disk space (<80% usage).
PASS All nodes are ready for validation.

System resource assessment:
  CPU cores: 32
  Memory: 376.16 GB
  Current load: 5.52
  Recommended concurrent nodes: 7

Do you want to generate new tech supports for analysis?
1. Generate new tech supports for analysis
2. Use existing tech supports on all nodes

Enter your choice (1/2): 1

================================================================================
  Tech Support Selection/Generation
================================================================================
Generating tech supports for all nodes in parallel.
Starting tech support collection on ND1. This may take several minutes...
Starting tech support collection on ND3. This may take several minutes...
Starting tech support collection on ND2. This may take several minutes...
Tech support collection started successfully on ND1
Tech support collection started successfully on ND2
Tech support collection started successfully on ND3
Found tech support file being generated on ND1, monitoring for completion...
Found tech support file being generated on ND2, monitoring for completion...
Found tech support file being generated on ND3, monitoring for completion...
Tech support still generating on ND1: 1.30 GB (+820.7 MB)...
Tech support still generating on ND3: 1.17 GB (+671.5 MB)...
Tech support still generating on ND2: 1.58 GB (+1225.8 MB)...
File size stable on ND1, performing verification checks...
File size stable on ND3, performing verification checks...
Tech support still generating on ND2: 2.15 GB (+583.2 MB)...
Tech support generation confirmed complete on ND1
PASS Tech support generated on ND1: /techsupport/2026-01-16T16-15-42Z-system-ts-ND1.tgz
Tech support generation confirmed complete on ND3
PASS Tech support generated on ND3: /techsupport/2026-01-16T16-15-41Z-system-ts-ND3.tgz
Generated tech support on ND3: 2026-01-16T16-15-41Z-system-ts-ND3.tgz
Generated tech support on ND1: 2026-01-16T16-15-42Z-system-ts-ND1.tgz
File size stable on ND2, performing verification checks...
Tech support generation confirmed complete on ND2
PASS Tech support generated on ND2: /techsupport/2026-01-16T16-15-45Z-system-ts-ND2.tgz
Generated tech support on ND2: 2026-01-16T16-15-45Z-system-ts-ND2.tgz

================================================================================
  Pre-Flight /tmp Space Validation
================================================================================
Checking /tmp disk space on all nodes before extraction...
This validation ensures sufficient space for tech support extraction (70% threshold).

Checking space on ND1... PASS
  Tech support: 1.30 GB | Current: 1.0% | Projected: 25.4%
Checking space on ND2... PASS
  Tech support: 2.15 GB | Current: 0.0% | Projected: 40.3%
Checking space on ND3... PASS
  Tech support: 1.17 GB | Current: 0.0% | Projected: 22.0%

PASS All nodes passed /tmp space validation!
Proceeding with worker script deployment...


================================================================================
  Deploying Worker Scripts and Starting Validation
================================================================================
Deploying worker script to node ND1...
Deploying worker script to node ND2...
Deploying worker script to node ND3...
PASS Worker script deployed to ND1
Starting validation on node ND1...
PASS Worker script deployed to ND2
Starting validation on node ND2...
PASS Worker script deployed to ND3
Starting validation on node ND3...
PASS Validation started on ND1
PASS Validation started on ND3
PASS Validation started on ND2

Monitoring validation progress on 3 nodes in batch 1...

Running validation checks on 3 Nexus Dashboard nodes...
[Node ND1] Validation complete
[Node ND3] Validation complete
[Node ND2] Validation complete
Collecting results and logs from all nodes...

Monitoring completed in 0 minutes 3 seconds


================================================================================
  Cleaning Up Temporary Files
================================================================================
Cleaning up temporary files from 3 nodes...
PASS Cleaned up temporary files on ND1
PASS Cleaned up temporary files on ND2
PASS Cleaned up temporary files on ND3

================================================================================
  Pre-upgrade Validation Report
================================================================================
Total validation time: 3 min 53 sec


Report generated on: 2026-01-16 11:18:06

[Check  1/20] Techsupport...                                                      PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     Tech support generated and extracted successfully
  ND2        PASS     Tech support generated and extracted successfully
  ND3        PASS     Tech support generated and extracted successfully

[Check  2/20] Version Check...                                                    PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     All cluster nodes are on the same version: 3.2.2f
  ND2        PASS     All cluster nodes are on the same version: 3.2.2f
  ND3        PASS     All cluster nodes are on the same version: 3.2.2f

[Check  3/20] Node Status...                                                      PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     All nodes in the cluster are in Active state
  ND2        PASS     All nodes in the cluster are in Active state
  ND3        PASS     All nodes in the cluster are in Active state

[Check  4/20] Ping Check...                                                       PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     Node can ping all mgmt and data ips in the cluster
  ND2        PASS     Node can ping all mgmt and data ips in the cluster
  ND3        PASS     Node can ping all mgmt and data ips in the cluster

[Check  5/20] Subnet Check...                                                     PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     Mgmt and Data interfaces are in different subnets
  ND2        PASS     Mgmt and Data interfaces are in different subnets
  ND3        PASS     Mgmt and Data interfaces are in different subnets

[Check  6/20] Persistent Ip Check...                                              PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     Found 10 persistent IP addresses (required: 5 for 3-node cluster)
  ND2        PASS     Found 10 persistent IP addresses (required: 5 for 3-node cluster)
  ND3        PASS     Found 10 persistent IP addresses (required: 5 for 3-node cluster)

[Check  7/20] Disk Space...                                                       PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     All directories are under 70% usage
  ND2        PASS     All directories are under 70% usage
  ND3        PASS     All directories are under 70% usage

[Check  8/20] Pod Status...                                                       PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     All Pods and Services are in a healthy state
  ND2        PASS     All Pods and Services are in a healthy state
  ND3        PASS     All Pods and Services are in a healthy state

[Check  9/20] System Health...                                                    PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     acs health indicates Node is healthy
  ND2        PASS     acs health indicates Node is healthy
  ND3        PASS     acs health indicates Node is healthy

[Check 10/20] Nxos Discovery Service...                                           PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     Deployment Mode is not ndfc-fabric-ndi
  ND2        PASS     Deployment Mode is not ndfc-fabric-ndi
  ND3        PASS     Deployment Mode is not ndfc-fabric-ndi

[Check 11/20] Backup Failure Check...                                             PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     All backup jobs completed successfully
  ND2        PASS     All backup jobs completed successfully
  ND3        PASS     All backup jobs completed successfully

[Check 12/20] Nameserver Duplicate Check...                                       PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     No duplicate nameservers found
  ND2        PASS     No duplicate nameservers found
  ND3        PASS     No duplicate nameservers found

[Check 13/20] Legacy Ndi Elasticsearch Check...                                   PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     Deployment mode contains NDI, check not applicable
  ND2        PASS     Deployment mode contains NDI, check not applicable
  ND3        PASS     Deployment mode contains NDI, check not applicable

[Check 14/20] Ntp Auth Check...                                                   PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     NTP Authentication not enabled
  ND2        PASS     NTP Authentication not enabled
  ND3        PASS     NTP Authentication not enabled

[Check 15/20] Certificate Check...                                                PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     No certificate issues found in SM logs
  ND2        PASS     No certificate issues found in SM logs
  ND3        PASS     No certificate issues found in SM logs

[Check 16/20] Iso Check...                                                        PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     No multiple ISO issues found
  ND2        PASS     No multiple ISO issues found
  ND3        PASS     No multiple ISO issues found

[Check 17/20] Lvm Pvs Check...                                                    PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     No empty Elasticsearch PVs found
  ND2        PASS     No empty Elasticsearch PVs found
  ND3        PASS     No empty Elasticsearch PVs found

[Check 18/20] Atom0 Nvme Check...                                                 PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     NVME drive seen by ND in PVS file
  ND2        PASS     NVME drive seen by ND in PVS file
  ND3        PASS     NVME drive seen by ND in PVS file

[Check 19/20] Atom0 Vg Check...                                                   PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     atom0 vg has more than 50G free space
  ND2        PASS     atom0 vg has more than 50G free space
  ND3        PASS     atom0 vg has more than 50G free space

[Check 20/20] Vnd App Large Check...                                              PASS
  Node       Status   Details
  ---------- -------- --------------------------------------------------
  ND1        PASS     ND is not SE-VIRTUAL-APP
  ND2        PASS     ND is not SE-VIRTUAL-APP
  ND3        PASS     ND is not SE-VIRTUAL-APP


Detailed results are available in /root/Downloads/preupgrade/final-results/

Results Bundle: /root/Downloads/preupgrade/nd-preupgrade-validation-results_2026-01-16T11-18-06.tgz

[root@localhost preupgrade]# ls -lh
total 516K
drwxr-xr-x. 2 root root  236 Jan 16 11:18 final-results
-rw-r--r--. 1 root root 204K Jan 16 11:12 ND-Preupgrade-Validation.py
-rw-r--r--. 1 root root  14K Jan 16 11:18 nd-preupgrade-validation-results_2026-01-16T11-18-06.tgz
-rw-r--r--. 1 root root  69K Jan 16 11:18 nd_validation_debug.log
-rw-r--r--. 1 root root 224K Jan 16 11:13 worker_functions.py

[root@localhost preupgrade]# ls -lh final-results/
total 144K
-rw-r--r--. 1 root root  14K Jan 16 11:17 ND1_output.log
-rw-r--r--. 1 root root 2.8K Jan 16 11:17 ND1_results.json
-rw-r--r--. 1 root root  14K Jan 16 11:18 ND2_output.log
-rw-r--r--. 1 root root 2.8K Jan 16 11:18 ND2_results.json
-rw-r--r--. 1 root root  14K Jan 16 11:18 ND3_output.log
-rw-r--r--. 1 root root 2.8K Jan 16 11:18 ND3_results.json
-rw-r--r--. 1 root root  68K Jan 16 11:18 nd_validation_debug.log
-rw-r--r--. 1 root root 7.2K Jan 16 11:18 validation_details.json
-rw-r--r--. 1 root root 7.7K Jan 16 11:18 validation_summary.txt
```

## Support

- Feedback and questions are welcome.
- If you have feedback or are encountering an issue running the script, please send an email to nd-preupgrade-validation@cisco.com
- If the script is recommending to open a Cisco TAC SR for any specific issue, please open a Cisco TAC SR.
- When opening a TAC SR, upload the `nd-preupgrade-validation-results*.tgz` file which includes all results and diagnostics.
- Running this script is not a requirement but it is intended to provide additional reassurance when planning for a Nexus Dashboard upgrade.
