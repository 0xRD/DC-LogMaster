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

Very useful for setting up lab environments and running tests for Purple Teaming.

---

## Table of Contents

1. [Synopsis](#synopsis)  
2. [Description](#description)  
3. [Requirements](#requirements)  
4. [Installation](#installation)  
5. [Usage](#usage)  
6. [Options](#options)  
7. [Categories](#categories)  
8. [Examples](#examples)  

---

## Synopsis

DC-LogMaster configures advanced audit policies on a Domain Controller using `auditpol` with subcategory GUIDs, ensuring language-independent operation and removing reliance on registry writes.

## Description

- Uses `auditpol /set` with GUIDs for each audit subcategory.  
- Eliminates localization issues on French, English, or other localized DCs.  
- Removes obsolete registry write steps; only advanced audit policy is applied.  
- Ideal for Purple Team labs and detection engineering exercises.

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

## Options

| Option           | Description                                                                                                  |
|------------------|--------------------------------------------------------------------------------------------------------------|
| `-ShowAvailable` | List categories and their Event IDs.                                                                         |
| `-ShowCurrent`   | Display current audit settings (via auditpol).                                                               |
| `-Enable <cats>` | Enable one or more categories (separate with commas): low, medium, high, accounts, groups, kerberos, objectaccess, policychange |
| `-Disable <cats>`| Disable one or more categories.                                                                              |
| `-WhatIf`        | Simulate actions without applying changes.                                                                   |
| `-h`, `--help`   | Show this help message.                                                                                      |

## Categories

- **low** (4624, 4625): Low verbosity (essential events)  
- **medium** (4768, 4769, 4771, 4776): Medium verbosity (additional events)  
- **high** (5136, 5137, 5138, 6400, 6401, 4662, 4663): High verbosity (detailed + object access)  
- **accounts** (4720, 4722, 4724, 4725, 4726): Account management events  
- **groups** (4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758): Security group management events  
- **kerberos** (4768, 4769, 4771, 4772, 4776, 4777): Kerberos authentication events  
- **objectaccess** (4662, 4663): Directory Service access events  
- **policychange** (4719): Audit Policy Change events  

## Examples

```powershell
# List all categories
.\Set-DCLogging.ps1 -ShowAvailable

# View current settings
.\Set-DCLogging.ps1 -ShowCurrent

# Simulate enabling low and accounts
.\Set-DCLogging.ps1 -Enable low,accounts -WhatIf

# Enable medium and high verbosity
.\Set-DCLogging.ps1 -Enable medium,high      

# Enable object access and policy change monitoring
.\Set-DCLogging.ps1 -Enable objectaccess,policychange

# Disable Kerberos auditing
.\Set-DCLogging.ps1 -Disable kerberos
```
