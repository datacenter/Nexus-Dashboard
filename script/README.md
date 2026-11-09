# ND-Pre-Upgrade-Validation-Script

The script checks for issues that are known to have an impact to the success of a Nexus Dashboard upgrade. Identification and remediation of such issues prior to upgrade can lead to more successful outcomes.

The script can be run from any Linux server with the required dependencies. If ACI APICs are available and have connectivity towards the ND management address, the script can be run from an APIC as these devices already contain all dependencies required to run the script. The script **cannot** be run from the Nexus Dashboard itself.

- The script can be run against any ND versions starting from Version 2.1.
- Due to a /tmp permissions discrepancy in ND version 4.1.1g, running the script against 4.1.1g setup triggers a new mode where the tech supports are downloaded to the local host that is running the script. This behavior is specific to 4.1.1g setups and does not apply to any other version.
- Port 443 connectivity is required between the host running the script and the Nexus Dashboard cluster for API related checks to run successfully. If Port 443 is not open, the API related checks will not work, but all other checks will complete successfully.
- **NDO / MSO validation (optional, `--ndo`):** the two base files plus `ndo_preupgrade.py` validate Nexus Dashboard Orchestrator (NDO, formerly MSO). This includes live from an ND cluster, offline from a techsupport or backup, and migration utilities for legacy MSO backups. NDO modes need **Python 3.8 or later** and no extra packages. See [NDO validation](#ndo-validation-optional---ndo).
- If you have feedback or are encountering an issue running the script, please send an email to nd-preupgrade-validation@cisco.com

**Ports required to be open between the local host and the ND cluster:**
- Port 22: Used for SSH and SCP operations
- Port 443: Used for API-based checks


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
  - [Passwords in scripts and automation](#passwords-in-scripts-and-automation)
  - [Example Run](#example-run)
- [NDO validation (optional, `--ndo`)](#ndo-validation-optional---ndo)
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
| 7 | Disk space | Verify all directories are under 80% utilization (`/logs/k8/kubelet`: 90% on ND 4.3 and later, where kubelet log rotation keeps that volume near 80%) | |
| 8 | Storage device check | Verify all storage devices exist | |
| 9 | Pod status | Verify all Pods and Services are in a healthy state | |
| 10 | System health | Verify all nodes are healthy using 'acs health' command | |
| 11 | Telemetry inband EPG check | Verify ACI NDI sites have inband EPG populated | [CSCws23607](https://bst.cisco.com/bugsearch/bug/CSCws23607) |
| 12 | Nxapi Cert Verify State check | Verify Nxapi Cert is disabled | |
| 13 | NXOS Discovery Service | Verify cisco-ndfc k8 App is not stuck in Disabling | [CSCwm97680](https://bst.cisco.com/bugsearch/bug/CSCwm97680) |
| 14 | Backup failure check | Verify latest backup is not in Failed or InProgress state | [CSCwq57968](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwq57968), [CSCwm96512](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm96512) |
| 15 | Nameserver duplicate check | Verify no duplicate nameservers exist in acs_system_config | |
| 16 | Legacy NDI ElasticSearch | Verify legacy NDI ElasticSearch LV does not exist for non-NDI deployments | [CSCwr43810](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwr43810) |
| 17 | NTP authentication check | Verify no NTP servers have authentication enabled | [CSCwr97181](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwr97181) |
| 18 | Certificate check | Verify no certificates have non-alphanumeric characters | [CSCwm35992](https://bst.cisco.com/bugsearch/bug/CSCwm35992) |
| 19 | ISO check | Verify multiple ISOs aren't found in boothook | [CSCwn94394](https://bst.cisco.com/bugsearch/bug/CSCwn94394) |
| 20 | Lvm Pvs check | Verify no empty ElasticSearch PVs are found | [CSCwe91228](https://bst.cisco.com/bugsearch/bug/CSCwe91228) |
| 21 | atom0 NVME check | Verify no NVME drive hardware failures are present in Physical node setups | |
| 22 | atom0 vg check | Verify there is more than 50% free space in atom0 virtual group | [CSCwr43515](https://bst.cisco.com/bugsearch/bug/CSCwr43515) |
| 23 | vND App Large check | Verify vND SE-VIRTUAL-APP is not using Large Profile | [CSCws77374](https://bst.cisco.com/bugsearch/bug/CSCws77374), [Documentation 1](https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/deployment/cisco-nexus-dashboard-deployment-guide-41x/nd-deploy-upgrade-41x.html#post-upgrade-tasks__section_vbs_1kz_jgc), [Documentation 2](https://www.cisco.com/c/en/us/td/docs/dcn/nd/3x/deployment/cisco-nexus-dashboard-and-services-deployment-guide-321/nd-deploy-esx-32x.html#concept_zkv_y2g_mmb) |
| 24 | Tenant reserved keyword check | Verify NDO/MSO tenants do not have reserved keyword prefix | [CSCwt87466](https://bst.cisco.com/bugsearch/bug/CSCwt87466) |

## Dependencies and Installation

### Python Requirements

| What you run | Python on the host running the script |
|---|---|
| ND validation (default, no `--ndo`) | **Python 3.7+** (also works on 3.6, the default `python3` on RHEL 8) |
| Any NDO mode (`--ndo ...`) | **Python 3.8+** |

The worker script runs on the ND nodes and is compatible with Python 2.7+ to accommodate older ND node versions. The ND nodes provide it; nothing extra is needed there.

No mode needs additional pip packages; NDO modes use only the Python standard library. If you start an NDO mode on an older Python, the script stops before connecting to anything and says which Python it needs.

**Getting Python 3.8+ for NDO modes** (these are OS packages, not pip):
- RHEL / Rocky / Alma 8: `sudo dnf install python39`, then run `python3.9 ND-Preupgrade-Validation.py --ndo ...`
- RHEL 9, Ubuntu 20.04 and later, and current macOS already ship Python 3.8 or later as `python3`.
- Check your version with `python3 --version`.

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

Default ND validation needs only these two files. Every NDO mode (`--ndo`), including
live, offline and standalone utilities, also needs `ndo_preupgrade.py` from the same
release in that directory. NDO requires Python 3.8+ and the standard library only.
The controller loads the add-on only when `--ndo` is supplied; `--help` works without it.

If the add-on is missing, NDO exits with code 1 before logging or connecting:

```text
Missing ndo_preupgrade.py: it must be in the same folder as ND-Preupgrade-Validation.py. ND-only validation does not need it.
```

A release/interface mismatch also exits with code 1: download the controller and
add-on from the same release.

### Compatibility Notes
- ND validation requires Python 3.7+ on the host running the script; it also runs on 3.6. NDO modes require Python 3.8+. See [Python Requirements](#python-requirements).
- The worker script is Python 2.7+ compatible to accommodate ND nodes on versions prior to 3.0.

### Passwords in scripts and automation
By default the script prompts for passwords; this is the recommended way. For unattended runs, set the password in the environment instead of on the command line:
- `ND_RESCUE_PASSWORD`: rescue-user password
- `ND_API_PASSWORD`: ND API password (optional; defaults to the rescue-user password)

The script reads these once and removes them from its environment. `-p/--password` and `--api-password` still work, but they are deprecated and print a warning. Any user on the same host can read a password given on the command line from the process list, and it is also saved in your shell history.

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
drwxr-xr-x 5 user user 4.0K May  1 01:59 Nexus-Dashboard

user@host:~$ ls -lh Nexus-Dashboard/
total 12K
-rw-r--r-- 1 user user  365 May  1 01:59 README.md
drwxr-xr-x 2 user user 4.0K May  1 01:59 plugin
drwxr-xr-x 2 user user 4.0K May  1 01:59 script

## Step 2: Navigate to the /script directory

user@host:~$ cd Nexus-Dashboard/script/
user@host:~/Nexus-Dashboard/script$ ls -lh
total 456K
-rw-r--r-- 1 user user 204K May  1 01:59 ND-Preupgrade-Validation.py
-rw-r--r-- 1 user user  21K May  1 01:59 README.md
-rw-r--r-- 1 user user 2.9K May  1 01:59 requirements.txt
-rw-r--r-- 1 user user 224K May  1 01:59 worker_functions.py

## Step 3: Run the ND-Preupgrade-Validation.py script

user@host:~/Nexus-Dashboard/script$ python3 ND-Preupgrade-Validation.py
Nexus Dashboard Pre-upgrade Validation Script
Running validation checks on 2026-02-19 18:46:10
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

Checking storage disks on all nodes...
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
  Current load: 3.51
  Recommended concurrent nodes: 7

Do you want to generate new tech supports for analysis?
1. Generate new tech supports for analysis
2. Use existing tech supports on all nodes

Enter your choice (1/2): 1


================================================================================
  Tech Support Selection/Generation
================================================================================
Generating tech supports for all nodes in parallel.
Starting tech support collection on ND2. This may take several minutes...
Starting tech support collection on ND1. This may take several minutes...
Starting tech support collection on ND3. This may take several minutes...
Tech support collection started successfully on ND1
Tech support collection started successfully on ND2
Tech support collection started successfully on ND3
Found tech support file being generated on ND3, monitoring for completion...
Found tech support file being generated on ND2, monitoring for completion...
Found tech support file being generated on ND1, monitoring for completion...
Tech support still generating on ND3: 1.28 GB (+815.7 MB)...
Tech support still generating on ND1: 1.39 GB (+967.7 MB)...
Tech support still generating on ND2: 1.58 GB (+1181.8 MB)...
File size stable on ND3, performing verification checks...
File size stable on ND1, performing verification checks...
Tech support still generating on ND2: 2.24 GB (+683.0 MB)...
Tech support generation confirmed complete on ND3
PASS Tech support generated on ND3: /techsupport/2026-02-19T23-53-14Z-system-ts-ND3.tgz
Tech support generation confirmed complete on ND1
PASS Tech support generated on ND1: /techsupport/2026-02-19T23-53-16Z-system-ts-ND1.tgz
Generated tech support on ND3: 2026-02-19T23-53-14Z-system-ts-ND3.tgz
Generated tech support on ND1: 2026-02-19T23-53-16Z-system-ts-ND1.tgz
File size stable on ND2, performing verification checks...
Tech support generation confirmed complete on ND2
PASS Tech support generated on ND2: /techsupport/2026-02-19T23-53-17Z-system-ts-ND2.tgz
Generated tech support on ND2: 2026-02-19T23-53-17Z-system-ts-ND2.tgz


================================================================================
  Pre-Flight /tmp Space Validation
================================================================================
Checking /tmp disk space on all nodes before extraction...
This validation ensures sufficient space for tech support extraction (70% threshold).

Checking space on ND1... PASS
  Tech support: 1.39 GB | Current: 1.0% | Projected: 27.2%
Checking space on ND2... PASS
  Tech support: 2.24 GB | Current: 1.0% | Projected: 43.1%
Checking space on ND3... PASS
  Tech support: 1.28 GB | Current: 16.0% | Projected: 40.1%

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
Total validation time: 4 min 2 sec
Report generated on: 2026-02-19 18:50:26

[Check  1/23] Techsupport...                                                      PASS
[Check  2/23] Version Check...                                                    PASS
[Check  3/23] Node Status...                                                      PASS
[Check  4/23] Ping Check...                                                       PASS
[Check  5/23] Subnet Check...                                                     PASS
[Check  6/23] Persistent Ip Check...                                              PASS
[Check  7/23] Disk Space...                                                       PASS
[Check  8/23] Storage Device Check...                                             PASS
[Check  9/23] Pod Status...                                                       PASS
[Check 10/23] System Health...                                                    PASS
[Check 11/23] Telemetry Inband Epg Check...                                       PASS
[Check 12/23] Nxapi Cert Verify State Check...                                    PASS
[Check 13/23] Nxos Discovery Service...                                           PASS
[Check 14/23] Backup Failure Check...                                             PASS
[Check 15/23] Nameserver Duplicate Check...                                       PASS
[Check 16/23] Legacy Ndi Elasticsearch Check...                                   PASS
[Check 17/23] Ntp Auth Check...                                                   PASS
[Check 18/23] Certificate Check...                                                PASS
[Check 19/23] Iso Check...                                                        PASS
[Check 20/23] Lvm Pvs Check...                                                    PASS
[Check 21/23] Atom0 Nvme Check...                                                 PASS
[Check 22/23] Atom0 Vg Check...                                                   PASS
[Check 23/23] Vnd App Large Check...                                              PASS
[Check 24/24] Reserved Tenant Names Check...                                      PASS

================================================================================
REPORT SUMMARY
================================================================================

PASS                         : 24
WARNING - ATTENTION REQUIRED : 0
FAIL - UPGRADE FAILURE!!     : 0

Detailed results are available in /home/user/Nexus-Dashboard/script/final-results/

Results Bundle: /home/user/Nexus-Dashboard/script/nd-preupgrade-validation-results_2026-05-01T02-50-26.tgz

user@host:~/Nexus-Dashboard/script$  ls -lh
total 564K
drwxr-xr-x. 2 root root  236 May  1 02:50 final-results
-rw-r--r--. 1 root root 240K May  1 02:45 ND-Preupgrade-Validation.py
-rw-r--r--. 1 root root  16K May  1 02:50 nd-preupgrade-validation-results_2026-05-01T02-50-26.tgz
-rw-r--r--. 1 root root 222K May  1 02:46 worker_functions.py

user@host:~/Nexus-Dashboard/script$  ls -lh final-results/
total 156K
-rw-r--r--. 1 root root  15K May  1 02:50 ND1_output.log
-rw-r--r--. 1 root root 2.8K May  1 02:50 ND1_results.json
-rw-r--r--. 1 root root  15K May  1 02:50 ND2_output.log
-rw-r--r--. 1 root root 2.8K May  1 02:50 ND2_results.json
-rw-r--r--. 1 root root  15K May  1 02:50 ND3_output.log
-rw-r--r--. 1 root root 2.8K May  1 02:50 ND3_results.json
-rw-r--r--. 1 root root  83K May  1 02:50 nd_validation_debug.log
-rw-r--r--. 1 root root 7.8K May  1 02:50 validation_details.json
-rw-r--r--. 1 root root 2.4K May  1 02:50 validation_summary.txt
```

## NDO validation (optional, `--ndo`)

Nexus Dashboard Orchestrator (NDO, formerly Multi-Site Orchestrator, MSO) validation is opt-in: add `--ndo`. Without `--ndo` the script behaves exactly as described above. NDO modes need Python 3.8+ and the sibling `ndo_preupgrade.py` add-on, with no extra packages.

The NDO checks and utilities support upgrade migrations, including from very old MSO releases (2.x and 3.x) to modern NDO.

| Mode | Command | What it does |
|---|---|---|
| Live ND + NDO | `python3 ND-Preupgrade-Validation.py --ndo --ndip <ND>` | All ND checks above, plus NDO checks on a fresh NDO database export collected during the run |
| Offline validation | `python3 ND-Preupgrade-Validation.py --ndo --tech-support <file>` | NDO checks on a file you already have. No ND connection and no credentials needed |
| Extract a backup | `python3 ND-Preupgrade-Validation.py --ndo --extract-backup <file> --output-dir <dir>` | Pulls the NDO Mongo backup out of a techsupport and prints its path and source release |
| Convert a legacy backup | `python3 ND-Preupgrade-Validation.py --ndo --convert-backup <file> --output-dir <dir> [--validation-only] [--run-ndo-checks --source-release "<MSO/NDO x.y.z>"] [--name <name>]` | Legacy MSO/NDO backup → validation JSON, so you can run the NDO checks on old data. A current-format database dump → a backup NDO can restore. |
| Native archive to JSON | `python3 ND-Preupgrade-Validation.py --ndo --mongodump-to-json <archive> --output-dir <dir> [--json-mode relaxed\|canonical]` | Converts a native `mongodump` archive to MongoDB Extended JSON |
| Standalone checks | `python3 ND-Preupgrade-Validation.py --ndo --check-backup <backup> --source-release "<NDO x.y.z>"` (or `--check-defects`) | Runs only the NDO data checks, or only the configuration checks, on a Mongo backup |

**Migrating from old MSO/NDO releases.** Validate first, then follow Cisco's restore-based migration: take a backup on the old release and restore the **original** backup on the intermediate release from the [Cisco migration guide](https://www.cisco.com/c/en/us/td/docs/dcn/mso/use-case/migrating-from-older-mso-ndo-to-nd.html). NDO converts legacy configuration itself during the restore. The converter does not create importable backups from legacy data. Use it to validate the data with `--convert-backup <file> --validation-only --run-ndo-checks` (add `--source-release "<MSO/NDO x.y.z>"` if the release cannot be detected).

**Offline inputs.** These are recognized by content, not file name:
- unified ND techsupports (`.tar`, `.tgz`);
- standalone MSO/NDO techsupports (`msc_report_*.zip`);
- NDO backups (`msc-backup-*.tar.gz`, `*.archive`);
- direct Mongo JSON exports.

The input file is never modified.

**What is checked.**
- **Data checks:** backup archive integrity, required Mongo collections, and JSON document integrity.
- **Configuration checks:** release-aware checks for known upgrade issues:
  - external-network references;
  - application BD names;
  - contract-filter EtherType;
  - SR-MPLS external subnet scope;
  - preferred-group shadow EPGs;
  - SR-MPLS L3Out dependency order;
  - tenant/site associations;
  - CloudSec UDP port control;
  - application-policy reference ownership.

  Only the checks that apply to your upgrade route run. The report shows the recommended upgrade route, based on the Cisco ND 4.3.1 upgrade matrix.
- **Snapshot age:** an NDO snapshot older than 24 hours is flagged, because you should validate current data.

**Results.**
- **Live and offline validation** write one report to `final-results/validation_summary.txt`
  and `final-results/validation_details.json`. With `--ndo`, NDO checks follow ND checks in
  the same numbered list, with one REPORT SUMMARY, NEXT STEPS block and UPGRADE ROUTE.
  Offline validation uses the same layout with only NDO rows.
- Each NDO finding includes an explanation and recommendation. The terminal and summary
  show an aligned table of at most five affected objects per finding; `ndo-findings.txt`
  contains every affected object. Snapshot timestamps use UTC and ages use hours, days or years.
- Per-node `<node>_output.log`, `<node>_results.json`, and `nd_validation_debug.log` remain
  at the top level for troubleshooting. NDO configuration diagnostics and retained export
  archives are under `ndo-evidence/`. Export bundle size limits still apply.
- `validation_details.json` retains the existing ND check mapping. Only `--ndo` adds an
  `ndo` object, containing NDO checks with global check numbers, full findings, snapshot,
  upgrade route, coverage and summary counts. Incomplete NDO coverage is `status: "WARNING"`
  with `coverage: "incomplete"`. A check that does not apply to the release is PASS and
  explains why.

For example, the end of a live report with 24 ND checks and four NDO checks looks like:

```text
[Check 25/28] NDO: Backup Archive Integrity...  PASS
[Check 26/28] NDO: Required Collections...      PASS
[Check 27/28] NDO: Document Integrity...        PASS
[Check 28/28] NDO: Configuration Checks...      WARNING - ATTENTION REQUIRED
  Finding 1 of 1: External network reference consistency (27 affected objects)
  Schema    Template  Site    Bridge domain  L3Out
  --------  --------  ------  -------------  -------
  Schema-A  Tmpl-1    Site-1  BD-web         L3Out-1
  Schema-A  Tmpl-1    Site-1  BD-app         L3Out-2
  Schema-A  Tmpl-1    Site-1  BD-db          L3Out-3
  Schema-A  Tmpl-1    Site-2  BD-web         L3Out-4
  Schema-A  Tmpl-1    Site-2  BD-app         L3Out-5
  ... 22 more (full list: final-results/ndo-findings.txt)

  Explanation:
  A bridge domain names an L3Out but has no saved reference to it.

  Recommendation:
  Re-select the L3Out in NDO and redeploy the affected template.
```

The usual `nd-preupgrade-validation-results_*.tgz` bundle is created in the current
working directory. It includes both reports, per-node files, debug log, complete
NDO findings and NDO evidence within the configured archive size limit. Upload it
to a TAC SR when asked. The duplicate `summary.txt`, `details.json` and
`diagnostics/nd/` copies are no longer produced by live/offline validation.
Default mode without `--ndo` retains its existing report, file layout and behavior.

**Standalone utilities.** `--extract-backup`, `--convert-backup`, `--mongodump-to-json`,
`--check-backup` and `--check-defects` keep their existing output formats and destinations.
The unified report applies to live/offline validation only.

**Exit codes (live/offline NDO validation).**

- **0:** no failed checks and complete NDO coverage. Review warnings.
- **2:** a failed check or incomplete NDO coverage. Incomplete coverage is displayed as
  `WARNING - COULD NOT FULLY EVALUATE` and included in the WARNING summary count.
- **1:** execution or input error. Argument usage errors return **2**.

## Support

- Feedback and questions are welcome.
- If you have feedback or are encountering an issue running the script, please send an email to nd-preupgrade-validation@cisco.com
- If the script is recommending to open a Cisco TAC SR for any specific issue, please open a Cisco TAC SR.
- When opening a TAC SR, upload the `nd-preupgrade-validation-results*.tgz` file which includes all results and diagnostics.
- Running this script is not a requirement but it is intended to provide additional reassurance when planning for a Nexus Dashboard upgrade.
