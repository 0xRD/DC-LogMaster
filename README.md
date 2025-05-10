# DC-LogMaster

**A PowerShell tool to manage and strengthen Domain Controller auditing via GPO and local registry.**

---

## Table of Contents

1. [Requirements](#requirements)  
2. [Installation](#installation)  
3. [Quick Usage](#quick-usage)  
4. [Options](#options)  
5. [Available Categories](#available-categories)  
6. [Internal Workflow](#internal-workflow)  
7. [Examples](#examples)  
---

## Requirements

- **Windows Server** (Domain Controller)  
- **PowerShell** ≥ 3.0  
- **GroupPolicy** module  
- Must be ran as **Administrator**  

---
## Installation

1. Clone or download this repository:  
   ```bash
   git clone https://github.com/0xRD/DC-LogMaster.git
   cd DC-LogMaster
   ```
2. Open PowerShell as Administrator.  
3. (Optional) Allow script execution:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
   ```

---

## Quick Usage

```powershell
.\DC-LogMaster.ps1 [options]
```

### Options

| Option          | Description |
|----------------|-------------|
| `-ShowAvailable` | Lists all available categories and their Event IDs |
| `-ShowCurrent`   | Displays the current local state (via registry) |
| `-Enable`        | Enables one or more categories |
| `-Disable`       | Disables one or more categories |
| `-WhatIf`        | Simulates the changes without applying them |
| `-h`, `--help`   | Displays this help message |

---

## Available Categories

| Category | Event IDs                            | Color    |
|----------|--------------------------------------|----------|
| `low`    | 4624, 4625                           | Green    |
| `medium` | 4768, 4769, 4771, 4776               | Yellow   |
| `high`   | 5136, 5137, 5138, 6400, 6401         | Red      |
| `accounts` | 4720, 4722, 4724, 4725, 4726       | Magenta  |
| `groups`   | 4727, 4728, 4732, 4756, 4757       | Cyan     |
| `kerberos` | 4768, 4769, 4771, 4772, 4776, 4777 | Yellow   |

---

## Internal Workflow

- `Get-Categories`: Defines a hashtable with categories (IDs + colors).
- `Show-Available`: Displays the categories defined in `Get-Categories`.
- `Show-Current`:  
  - Reads values from `HKLM:\System\CurrentControlSet\Control\Lsa\Audit*`  
  - Converts DWORD values to human-readable status (Disabled, Success, etc.)  
  - Displays ID, subcategory, and status, with color formatting.
- `Update-Categories`:  
  - Validates category names (ToLowerInvariant + ContainsKey)  
  - Uses `Set-GPRegistryValue` to edit GPO (Preferences → Registry)  
  - Uses `Set-ItemProperty` for immediate local registry update  
  - Calls `Invoke-GPUpdate -Force` to force GPO application
- `Get-AuditMapping`: Maps each ID to its subcategory name and registry path.

---

## Examples

```powershell
# View all categories
.\DC-LogMaster.ps1 -ShowAvailable

# View current local audit status
.\DC-LogMaster.ps1 -ShowCurrent

# Simulate enabling categories
.\DC-LogMaster.ps1 -Enable low,accounts -WhatIf

# Enable medium and high categories
.\DC-LogMaster.ps1 -Enable medium high

# Disable kerberos category
.\DC-LogMaster.ps1 -Disable kerberos

# Display help
.\DC-LogMaster.ps1 -h
```
---

