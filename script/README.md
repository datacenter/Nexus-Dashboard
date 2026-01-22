# ND-Pre-Upgrade-Validation-Script

The script checks for issues that are known to have an impact to the success of a Nexus Dashboard upgrade. Identification and remediation of such issues prior to upgrade can lead to more successful outcomes.

The script can be run from any Linux server with the required dependencies. If ACI APICs are available and have connectivity towards the ND management address, the script can be run from an APIC as these devices already contain all dependencies required to run the script. The script **cannot** be run from the Nexus Dashboard itself.

- The script can be run against any ND versions starting from Version 2.1.
- Due to a /tmp permissions discrepancy, running the script on 4.1.1g requires root access.
- If you have feedback or are encountering an issue running the script, please send an email to nd-preupgrade-validation@cisco.com

<video src="https://github.com/user-attachments/assets/0bcbc1f0-98c0-4e8f-8cfe-20265f52779e" controls></video>
Note: The cloning instructions differ slightly from the video now that the repo has moved. 
- The clone command required is `git clone https://github.com/datacenter/Nexus-Dashboard.git`
- See the [Example Run](#example-run) section for addition detail.

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
| 10 | Telemetry inband EPG check | Verify ACI NDI sites have inband EPG populated | [CSCws23607](https://bst.cisco.com/bugsearch/bug/CSCws23607) |
| 11 | NXOS Discovery Service | Verify cisco-ndfc k8 App is not stuck in Disabling | [CSCwm97680](https://bst.cisco.com/bugsearch/bug/CSCwm97680) |
| 12 | Backup failure check | Verify latest backup is not in Failed or InProgress state | [CSCwq57968](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwq57968), [CSCwm96512](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm96512) |
| 13 | Nameserver duplicate check | Verify no duplicate nameservers exist in acs_system_config | |
| 14 | Legacy NDI ElasticSearch | Verify legacy NDI ElasticSearch LV does not exist for non-NDI deployments | [CSCwr43810](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwr43810) |
| 15 | NTP authentication check | Verify no NTP servers have authentication enabled | [CSCwr97181](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwr97181) |
| 16 | Certificate check | Verify no certificates have non-alphanumeric characters | [CSCwm35992](https://bst.cisco.com/bugsearch/bug/CSCwm35992) |
| 17 | ISO check | Verify multiple ISOs aren't found in boothook | [CSCwn94394](https://bst.cisco.com/bugsearch/bug/CSCwn94394) |
| 18 | Lvm Pvs check | Verify no empty ElasticSearch PVs are found | [CSCwe91228](https://bst.cisco.com/bugsearch/bug/CSCwe91228) |
| 19 | atom0 NVME check | Verify no NVME drive hardware failures are present in Physical node setups | |
| 20 | atom0 vg check | Verify there is more than 50% free space in atom0 virtual group | [CSCwr43515](https://bst.cisco.com/bugsearch/bug/CSCwr43515) |
| 21 | vND App Large check | Verify vND SE-VIRTUAL-APP is not using Large Profile | [CSCws77374](https://bst.cisco.com/bugsearch/bug/CSCws77374), [Documentation 1](https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/cisco-nexus-dashboard-deployment-guide-41x/nd-deploy-upgrade-41x.html#post-upgrade-tasks__section_vbs_1kz_jgc), [Documentation 2](https://www.cisco.com/c/en/us/td/docs/dcn/nd/3x/deployment/cisco-nexus-dashboard-and-services-deployment-guide-321/nd-deploy-esx-32x.html#concept_zkv_y2g_mmb) |

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
## Step 1: Clone the repo

user@host:~$ git clone https://github.com/datacenter/Nexus-Dashboard.git
Cloning into 'Nexus-Dashboard'...
remote: Enumerating objects: 17, done.
remote: Counting objects: 100% (17/17), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 17 (delta 4), reused 17 (delta 4), pack-reused 0 (from 0)
Receiving objects: 100% (17/17), 90.19 KiB | 1.64 MiB/s, done.
Resolving deltas: 100% (4/4), done.

user@host:~$ ls -lh
total 12K
drwxr-xr-x 5 user user 4.0K Jan 21 22:59 Nexus-Dashboard

user@host:~$ ls -lh Nexus-Dashboard/
total 12K
-rw-r--r-- 1 user user  365 Jan 21 22:59 README.md
drwxr-xr-x 2 user user 4.0K Jan 21 22:59 plugin
drwxr-xr-x 2 user user 4.0K Jan 21 22:59 script

## Step 2: Navigate to the /script directory

user@host:~$ cd Nexus-Dashboard/script/
user@host:~/Nexus-Dashboard/script$ ls -lh
total 456K
-rw-r--r-- 1 user user 204K Jan 21 22:59 ND-Preupgrade-Validation.py
-rw-r--r-- 1 user user  21K Jan 21 22:59 README.md
-rw-r--r-- 1 user user 2.9K Jan 21 22:59 requirements.txt
-rw-r--r-- 1 user user 224K Jan 21 22:59 worker_functions.py

## Step 3: Run the ND-Preupgrade-Validation.py script

user@host:~/Nexus-Dashboard/script$ python3 ND-Preupgrade-Validation.py
Nexus Dashboard Pre-upgrade Validation Script
Running validation checks on 2026-01-21 22:59:51
Enter Nexus Dashboard IP address: 1.1.1.1
Enter password for rescue-user:

Connecting to Nexus Dashboard at 1.1.1.1...
Successfully connected to Nexus Dashboard at 1.1.1.1
Nexus Dashboard version: 3.2.2f
Discovering Nexus Dashboard nodes...
Found 3 Nexus Dashboard nodes
---------------------------------------
        ND1 (1.1.1.1)
        ND2 (1.1.1.2)
        ND3 (1.1.1.3)
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
  Current load: 4.1
  Recommended concurrent nodes: 7

Do you want to generate new tech supports for analysis?
1. Generate new tech supports for analysis
2. Use existing tech supports on all nodes

Enter your choice (1/2): 1


================================================================================
  Tech Support Selection/Generation
================================================================================
Generating tech supports for all nodes in parallel.
Starting tech support collection on ND3. This may take several minutes...
Starting tech support collection on ND1. This may take several minutes...
Starting tech support collection on ND2. This may take several minutes...
Tech support collection started successfully on ND3
Tech support collection started successfully on ND1
Tech support collection started successfully on ND2
Found tech support file being generated on ND3, monitoring for completion...
Found tech support file being generated on ND1, monitoring for completion...
Found tech support file being generated on ND2, monitoring for completion...
Tech support still generating on ND3: 1.19 GB (+650.4 MB)...
Tech support still generating on ND1: 1.32 GB (+806.0 MB)...
Tech support still generating on ND2: 1.61 GB (+1199.0 MB)...
File size stable on ND3, performing verification checks...
File size stable on ND1, performing verification checks...
Tech support still generating on ND2: 2.20 GB (+601.0 MB)...
Tech support generation confirmed complete on ND1
Tech support generation confirmed complete on ND3
PASS Tech support generated on ND1: /techsupport/2026-01-22T04-02-23Z-system-ts-ND1.tgz
PASS Tech support generated on ND3: /techsupport/2026-01-22T04-02-22Z-system-ts-ND3.tgz
Generated tech support on ND3: 2026-01-22T04-02-22Z-system-ts-ND3.tgz
Generated tech support on ND1: 2026-01-22T04-02-23Z-system-ts-ND1.tgz
File size stable on ND2, performing verification checks...
Tech support generation confirmed complete on ND2
PASS Tech support generated on ND2: /techsupport/2026-01-22T04-02-26Z-system-ts-ND2.tgz
Generated tech support on ND2: 2026-01-22T04-02-26Z-system-ts-ND2.tgz


================================================================================
  Pre-Flight /tmp Space Validation
================================================================================
Checking /tmp disk space on all nodes before extraction...
This validation ensures sufficient space for tech support extraction (70% threshold).

Checking space on ND1... PASS
  Tech support: 1.32 GB | Current: 1.0% | Projected: 25.8%
Checking space on ND2... PASS
  Tech support: 2.20 GB | Current: 0.0% | Projected: 41.3%
Checking space on ND3... PASS
  Tech support: 1.19 GB | Current: 16.0% | Projected: 38.4%

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
Total validation time: 3 min 56 sec
Report generated on: 2026-01-21 23:03:59

[Check  1/21] Techsupport...                                                      PASS
[Check  2/21] Version Check...                                                    PASS
[Check  3/21] Node Status...                                                      PASS
[Check  4/21] Ping Check...                                                       PASS
[Check  5/21] Subnet Check...                                                     PASS
[Check  6/21] Persistent Ip Check...                                              PASS
[Check  7/21] Disk Space...                                                       PASS
[Check  8/21] Pod Status...                                                       PASS
[Check  9/21] System Health...                                                    PASS
[Check 10/21] Telemetry Inband Epg Check...                                       PASS
[Check 11/21] Nxos Discovery Service...                                           PASS
[Check 12/21] Backup Failure Check...                                             PASS
[Check 13/21] Nameserver Duplicate Check...                                       PASS
[Check 14/21] Legacy Ndi Elasticsearch Check...                                   PASS
[Check 15/21] Ntp Auth Check...                                                   PASS
[Check 16/21] Certificate Check...                                                PASS
[Check 17/21] Iso Check...                                                        PASS
[Check 18/21] Lvm Pvs Check...                                                    PASS
[Check 19/21] Atom0 Nvme Check...                                                 PASS
[Check 20/21] Atom0 Vg Check...                                                   PASS
[Check 21/21] Vnd App Large Check...                                              PASS


================================================================================
REPORT SUMMARY
================================================================================

PASS                         : 21
WARNING - ATTENTION REQUIRED : 0
FAIL - UPGRADE FAILURE!!     : 0

Detailed results are available in /home/user/Nexus-Dashboard/script/final-results/

Results Bundle: /home/user/Nexus-Dashboard/script/nd-preupgrade-validation-results_2026-01-17T14-46-01.tgz

user@host:~/Nexus-Dashboard/script$ ls -lh
total 516K
total 532K
drwxr-xr-x. 2 user user  236 Jan 21 23:03 final-results
-rw-r--r--. 1 user user 228K Jan 21 22:59 ND-Preupgrade-Validation.py
-rw-r--r--. 1 user user  21K Jan 21 22:59 README.md
-rw-r--r--. 1 user user  14K Jan 21 23:03 nd-preupgrade-validation-results_2026-01-21T23-03-59.tgz
-rw-r--r--. 1 user user  69K Jan 21 23:03 nd_validation_debug.log
-rw-r--r--. 1 user user 215K Jan 21 22:59 worker_functions.py

user@host:~/Nexus-Dashboard/script$ ls -lh final-results/
total 140K
-rw-r--r--. 1 user user  14K Jan 21 23:03 ND1_output.log
-rw-r--r--. 1 user user 2.8K Jan 21 23:03 ND1_results.json
-rw-r--r--. 1 user user  14K Jan 21 23:03 ND2_output.log
-rw-r--r--. 1 user user 2.8K Jan 21 23:03 ND2_results.json
-rw-r--r--. 1 user user  14K Jan 21 23:03 ND3_output.log
-rw-r--r--. 1 user user 2.8K Jan 21 23:03 ND3_results.json
-rw-r--r--. 1 user user  68K Jan 21 23:03 nd_validation_debug.log
-rw-r--r--. 1 user user 7.5K Jan 21 23:03 validation_details.json
-rw-r--r--. 1 user user 2.3K Jan 21 23:03 validation_summary.txt
```

## Support

- Feedback and questions are welcome.
- If you have feedback or are encountering an issue running the script, please send an email to nd-preupgrade-validation@cisco.com
- If the script is recommending to open a Cisco TAC SR for any specific issue, please open a Cisco TAC SR.
- When opening a TAC SR, upload the `nd-preupgrade-validation-results*.tgz` file which includes all results and diagnostics.
- Running this script is not a requirement but it is intended to provide additional reassurance when planning for a Nexus Dashboard upgrade.
