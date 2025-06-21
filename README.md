# DC-LogMaster

```text
       |>>>                      |>>>
       |                         |
   _   ꓕ   _                 _   ꓕ   _
  |;|_|;|_|;|               |;|_|;|_|;|
  \\.    .  /               \\.    .  /
   \\:  .  /                 \\:  .  /
    ||:   |                   ||:   |
    ||:.  |                   ||:.  |
    ||:  .|                   ||:  .|
    ||:   |                   ||:   |
    ||: , |                   ||: , |
    ||:   |                   ||:   |
    ||:   |                   ||:   |
   /||:.  |\\                /||:.  |\\
  /_||::._|_\\              /_||::._|_\\
```

A PowerShell tool to manage and strengthen Domain Controller audit settings.

Very useful for setting up lab environments and running tests for Purple Teaming.

---

## Table of Contents

1. [Synopsis](#synopsis)
2. [Description](#description)
3. [Important Note on Group Policy Precedence](#important-note-on-group-policy-precedence)
4. [Key Features](#key-features)
5. [Requirements](#requirements)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Options](#options)
9. [Categories](#categories)
10. [Examples](#examples)
11. [Logging](#logging)

---

## Synopsis

DC-LogMaster is a PowerShell tool designed to help administrators view and configure Advanced Audit Policy settings on Windows Domain Controllers. It primarily uses `auditpol.exe` for managing these settings locally. The script now includes features to detect potential GPO conflicts, log its operations, and export/import audit policy configurations.

**Version:** 1.1.0 (Reflects script version)

## Description

This tool facilitates the management of granular audit subcategories critical for security monitoring on Domain Controllers. It aims to simplify enabling comprehensive logging based on predefined event ID groups or by manipulating the full audit policy.

## Important Note on Group Policy Precedence

**Advanced Audit Policy settings are most commonly and effectively managed via Group Policy Objects (GPOs) in an Active Directory environment.**

*   Settings applied by GPOs will **always override** local audit policy settings configured by `auditpol.exe` (which this script uses for modifications).
*   This script now attempts to **detect GPOs** that might be configuring Advanced Audit Policy settings.
    *   If such GPOs are detected, the script will issue a **warning** before you attempt to change local policy settings, as your changes are likely to be ineffective or temporary.
    *   It is **strongly recommended** to manage audit policies through the identified GPOs for consistency and reliability in a production environment.
*   Use this script to modify local policies primarily in standalone environments, testing labs, or when you are certain no overriding GPOs are in effect for Advanced Audit Policy.

## Key Features

- **View Current Audit Policy**: Displays current audit settings. Tries to show a detailed view of all subcategories from `auditpol /get /category:* /r`, falling back to a predefined category view if needed.
- **Modify Audit Policy**: Enable or disable audit settings for predefined logical groups of event IDs (categories) or for all categories.
- **GPO Conflict Detection**: Attempts to identify if Advanced Audit Policy is managed by GPOs and warns the user.
- **Export/Import Audit Policy**:
    -   Export the current local audit policy settings to a file using `auditpol /backup`.
    -   Import audit policy settings from a file using `auditpol /restore`. (Subject to GPO override).
- **Logging**: All operations, warnings, and errors are logged to a specified file (default: `DC-LogMaster.log` in the script's directory).
- **Language Independent**: Uses subcategory GUIDs with `auditpol.exe` to avoid localization issues.

## Requirements

- **Windows Server** (Domain Controller recommended for full GPO detection context)
- **PowerShell** ≥ 3.0 (PS 5.1+ recommended)
- **ActiveDirectory** PowerShell Module (for GPO detection to determine DC's OU)
- **GroupPolicy** PowerShell Module (for GPO detection and potential future GPO management features)
- Running as **Administrator** (required for `auditpol.exe` and GPO queries)

## Installation

1. Clone or download this repository:

   ```bash
   git clone https://github.com/0xRD/DC-LogMaster.git
   cd DC-LogMaster
   ```

2. Open PowerShell as Administrator.

## Usage

```powershell
.\Set-DCLogging.ps1 [options]
```

## Options

| Option                   | Alias    | Description                                                                                                                                 |
|--------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `-h`, `-?`               | `Help`   | Show the help message.                                                                                                                      |
| `-ShowAvailable`         |          | List available audit categories and their associated Event IDs.                                                                             |
| `-ShowCurrent`           |          | Display current local audit settings. Attempts a detailed view via `auditpol /get /category:* /r` first.                                      |
| `-Enable <categories>`   |          | Enable auditing for one or more specified categories (e.g., "low,accounts", or "all").                                                      |
| `-Disable <categories>`  |          | Disable auditing for one or more specified categories.                                                                                      |
| `-ExportPolicy <filepath>`|          | Export the current local audit policy settings to the specified file using `auditpol /backup`.                                              |
| `-ImportPolicy <filepath>`|          | Import local audit policy settings from the specified file using `auditpol /restore`. **Warning:** GPOs may override these settings. A reboot may be required. |
| `-LogFilePath <filepath>`|          | Specify the path for the log file. Defaults to `.\DC-LogMaster.log`.                                                                        |
| `-WhatIf`                |          | Simulate actions that would change audit policy without actually applying them. Affects `Enable`, `Disable`, `ImportPolicy`, `ExportPolicy`. |

## Categories

The script defines several logical categories that group related audit subcategories and their event IDs. When using `-Enable` or `-Disable` with these categories, the script attempts to configure all associated audit subcategories.

Below are the categories, their typical log impact, and a brief description:

-   **`low`**
    -   **Event IDs**: 4624 (Logon), 4625 (Logoff)
    -   **Log Impact**: Low
    -   **Description**: Captures essential successful user logons and logoffs. These are fundamental for tracking user activity and are generally low volume on typical systems but can increase on very busy servers. High security value.

-   **`medium`**
    -   **Event IDs**: 4768 (Kerberos AuthN TGT Request), 4769 (Kerberos Service Ticket Request), 4771 (Kerberos Pre-Auth Failed), 4776 (NTLM AuthN)
    -   **Log Impact**: Medium
    -   **Description**: Focuses on authentication protocols. Kerberos events (4768, 4769) are common on DCs. NTLM (4776) is important to monitor for legacy protocol usage or potential pass-the-hash attacks. 4771 (Kerberos Pre-Auth Failed) can indicate bad password attempts or Kerberoasting. Volume can be moderate to high on busy DCs.

-   **`high`**
    -   **Event IDs**: 5136, 5137, 5138 (Directory Service Changes), 6400, 6401 (KDC Policy Change), 4662 (Object Operation), 4663 (Object Access Attempt)
    -   **Log Impact**: High (Potentially Noisy)
    -   **Description**: Includes detailed Directory Service object changes and access attempts. Events 4662/4663 are part of the `objectaccess` category and are extremely verbose if not targeted with SACLs. DS change events (5136-5138) are critical for tracking AD modifications. KDC policy changes are rare but important. This category can generate significant noise if `objectaccess` subcategories are broadly enabled.

-   **`accounts`**
    -   **Event IDs**: 4720 (User Created), 4722 (User Enabled), 4724 (Password Reset Attempt), 4725 (User Disabled), 4726 (User Deleted)
    -   **Log Impact**: Medium
    -   **Description**: Tracks user account lifecycle events. Critical for security monitoring. Volume is generally low to medium, corresponding to administrative activity.

-   **`groups`**
    -   **Event IDs**: 4727-4730 (Global Group Mgmt), 4731-4735, 4737 (Local Group Mgmt), 4754-4758 (Universal Group Mgmt)
    -   **Log Impact**: Medium
    -   **Description**: Tracks security and distribution group management activities (creation, deletion, member changes). Essential for monitoring privilege escalation or unauthorized modifications. Volume is typically low to medium.

-   **`kerberos`**
    -   **Event IDs**: 4768 (TGT Request), 4769 (Service Ticket Req), 4771 (Pre-Auth Failed), 4772 (TGS Request Failed), 4776 (NTLM AuthN - often included for broader auth view), 4777 (NTLM AuthN Failed)
    -   **Log Impact**: Medium to High (Depends on activity)
    -   **Description**: Provides a comprehensive view of Kerberos (and often NTLM) authentication events, including failures. Volume can be high on busy DCs. Critical for detecting various attacks (Kerberoasting, brute force, etc.).

-   **`objectaccess`**
    -   **Event IDs**: 4662 (Object Operation Performed), 4663 (Object Access Attempted)
    -   **Log Impact**: Very High (Use with targeted SACLs)
    -   **Description**: Audits access to specific AD DS objects. **These events are extremely verbose if enabled broadly.** To be useful, you MUST configure specific Security Access Control Lists (SACLs) on the objects you want to monitor. Without targeted SACLs, this will flood your event logs.

-   **`policychange`**
    -   **Event IDs**: 4719 (Audit Policy Changed)
    -   **Log Impact**: Low to Medium (Important for security)
    -   **Description**: Tracks changes to the audit policy itself. This is a critical event to monitor to ensure audit settings are not tampered with. Volume is typically very low.

### Log Impact Legend:
*   **Low**: Minimal event log noise, typically essential security events.
*   **Medium**: Moderate event volume, useful for broader monitoring.
*   **High (Potentially Noisy)**: Significant event volume, may require tuning or specific focus.
*   **Medium to High (Depends on activity)**: Volume varies with system activity.
*   **Very High (Use with targeted SACLs)**: Can generate extreme volume if not carefully configured (e.g., Object Access).
*   **Low to Medium (Important for security)**: Important events, volume usually manageable.


## Examples

```powershell
# List all categories
.\Set-DCLogging.ps1 -ShowAvailable

# View current settings
.\Set-DCLogging.ps1 -ShowCurrent

# Simulate enabling low and accounts
.\Set-DCLogging.ps1 -Enable low,accounts -WhatIf

# Enable medium and high verbosity
.\DC-LogMaster.ps1 -Enable medium,high

# Enable object access and policy change monitoring, log to a custom file
.\DC-LogMaster.ps1 -Enable objectaccess,policychange -LogFilePath C:\temp\dc_audit.log

# Disable Kerberos auditing
.\DC-LogMaster.ps1 -Disable kerberos

# Export current audit policy
.\DC-LogMaster.ps1 -ExportPolicy C:\temp\current_audit_policy.csv

# Import audit policy from a file
.\DC-LogMaster.ps1 -ImportPolicy C:\temp\baseline_audit_policy.csv
```

## Logging

The script logs its operations, warnings, and errors to a log file.
- By default, the log file is `DC-LogMaster.log` created in the same directory as the script.
- Use the `-LogFilePath <filepath>` parameter to specify a custom path for the log file.

The log includes:
- Script start and end times.
- Command-line arguments used.
- GPO detection results and warnings.
- Actions taken (e.g., enabling/disabling categories, export/import operations).
- Success or failure of `auditpol.exe` commands, including exit codes for failures.
- Any errors encountered during script execution.

Reviewing this log file is crucial for troubleshooting and verifying the script's actions.
