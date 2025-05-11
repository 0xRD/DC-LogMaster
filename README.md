
```
       |>>>                    |>>>
       |                        |
   _  _|_  _                _  _|_  _
  |;|_|;|_|;|              |;|_|;|_|;|
  \\.    .  /              \\.    .  /
   \\:  .  /                \\:  .  /
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

# DC-LogMaster

A PowerShell tool to manage and strengthen Domain Controller audit settings.

---

## Table of Contents

1. [Synopsis](#synopsis)  
2. [Description](#description)  
3. [Requirements](#requirements)  
4. [Installation](#installation)  
5. [Usage](#usage)  
6. [Options](#options)  
7. [Examples](#examples)  
8. [To Do](#to-do)  
---

## Synopsis

DC-LogMaster configures advanced audit policies on a Domain Controller using `auditpol` with subcategory GUIDs, ensuring language-independent operation and removing reliance on registry writes.

## Description

- Uses `auditpol /set` with GUIDs for each audit subcategory.  
- Eliminates localization issues on French, English, or other localized DCs.  
- Removes obsolete registry write steps; only advanced audit policy is applied.

## Requirements

- **Windows Server** (Domain Controller)  
- **PowerShell** ≥ 3.0  
- **GroupPolicy** module  
- Running as **Administrator**

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

### Options

| Option           | Description                                        |
|------------------|----------------------------------------------------|
| `-ShowAvailable` | List categories and their Event IDs.               |
| `-ShowCurrent`   | Display current audit settings (registry values).  |
| `-Enable <cats>` | Enable one or more categories (low, medium, high, accounts, groups, kerberos). |
| `-Disable <cats>`| Disable one or more categories.                    |
| `-WhatIf`        | Simulate actions without applying changes.         |
| `-h`, `--help`   | Show this help message.                            |

## Examples

```powershell
# List all categories
.\Set-DCLogging.ps1 -ShowAvailable

# View current settings
.\Set-DCLogging.ps1 -ShowCurrent

# Simulate enabling low and accounts
.\Set-DCLogging.ps1 -Enable low,accounts -WhatIf

# Enable medium and high verbosity
.\Set-DCLogging.ps1 -Enable medium high

# Disable Kerberos auditing
.\Set-DCLogging.ps1 -Disable kerberos
```
