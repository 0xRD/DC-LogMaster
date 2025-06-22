<#
.SYNOPSIS
    View-DCEffectiveAuditPolicy: Displays detailed effective audit policy settings
    on a machine, correlating them with known Event IDs where possible.
.DESCRIPTION
    This script retrieves the current advanced audit policy settings using 'auditpol.exe /get /category:* /r'.
    It then attempts to parse this output and, for each subcategory, display its status along with
    any associated Event IDs that are mapped within this script (based on mappings from DC-LogMaster).
    This tool is for viewing only and does not modify any settings.
.NOTES
    Author: Jules (AI Agent)
    Version: 1.0.0
    This script is a companion to DC-LogMaster.ps1 and reuses some of its data structures for
    Event ID mapping.
.EXAMPLE
    .\View-DCEffectiveAuditPolicy.ps1
    Displays the current effective audit policy with associated Event IDs.

.EXAMPLE
    .\View-DCEffectiveAuditPolicy.ps1 -LogFilePath C:\temp\audit_view.log
    Displays the policy and logs operations to the specified file.
#>
[CmdletBinding()]
param(
    [alias('h','?')][switch] $Help,
    [string] $LogFilePath = ".\View-DCEffectiveAuditPolicy.log"
)

# Script Version
$ScriptVersion = "1.0.0"

# Initial LogFilePath check
if ($PSBoundParameters.ContainsKey('LogFilePath')) {
    $initialLogDir = Split-Path -Path $LogFilePath -Parent
    if ($initialLogDir -and (-not (Test-Path -Path $initialLogDir -PathType Container))) {
        Write-Error "Initial check: Parent directory '$initialLogDir' for specified LogFilePath '$LogFilePath' does not exist. Script will likely fail to log to file."
    }
}

# --- BEGIN LOGGING FUNCTION ---
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] - $Message"

    try {
        Out-File -FilePath $LogFilePath -Append -InputObject $logEntry -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Error "FATAL: Could not write to log file '$LogFilePath'. Error: $($_.Exception.Message)"
    }

    switch ($Level) {
        "INFO"  { Write-Host $logEntry }
        "WARN"  { Write-Warning $logEntry }
        "ERROR" { Write-Error $logEntry }
        "DEBUG" { Write-Debug $logEntry } # Use Write-Host for DEBUG if not running in a context where Write-Debug is visible
        default { Write-Host $logEntry }
    }
}
# --- END LOGGING FUNCTION ---

# --- BEGIN CORE AUDIT POLICY FUNCTIONS ---

function Get-EffectiveAuditPolicyDetailed {
    [CmdletBinding()]
    param()

    Write-Log -Message "Attempting to retrieve detailed audit policy settings using 'auditpol /get /category:* /r'." -Level INFO
    try {
        $csvOutput = auditpol /get /category:* /r | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Log -Message "'auditpol /get /category:* /r' failed. Exit code: $LASTEXITCODE. Output: $csvOutput" -Level ERROR
            return $null
        }

        $lines = $csvOutput -split [System.Environment]::NewLine
        $csvDataLines = New-Object System.Collections.Generic.List[string]
        $headerFound = $false
        foreach ($line in $lines) {
            if ($line -match "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting") {
                $headerFound = $true
            }
            if ($headerFound -and -not ([string]::IsNullOrWhiteSpace($line))) {
                $csvDataLines.Add($line)
            }
        }

        if ($csvDataLines.Count -lt 2) {
            Write-Log -Message "Could not parse CSV output from auditpol. No data lines found after header." -Level WARN
            Write-Log -Message "Raw auditpol output for /r: $csvOutput" -Level DEBUG
            return $null
        }

        $policies = ConvertFrom-Csv -InputObject ($csvDataLines -join [System.Environment]::NewLine)
        Write-Log -Message "Successfully parsed $($policies.Count) audit policy entries from 'auditpol /get /category:* /r'." -Level INFO
        return $policies
    } catch {
        Write-Log -Message "An error occurred while getting or parsing detailed audit policy: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "Raw auditpol output for /r (on exception): $csvOutput" -Level DEBUG
        return $null
    }
}

# Global GUID map: RegistryPath -> Subcategory GUID (from auditpol export in DC-LogMaster)
# This map helps link Subcategory GUIDs (from auditpol output) back to a conceptual 'RegistryPath'
# which is then used by Get-AuditMapping to find associated Event IDs.
$AdvSubCatGuidMap = @{
    'AuditLogon'                           = '{0CCE9215-69AE-11D9-BED3-505054503030}' # Logon
    'AuditLogoff'                          = '{0CCE9216-69AE-11D9-BED3-505054503030}' # Logoff
    'AuditAccountLockout'                  = '{0CCE9217-69AE-11D9-BED3-505054503030}' # Account Lockout
    'AuditIPsecMainMode'                   = '{0CCE9218-69AE-11D9-BED3-505054503030}' # IPsec Main Mode
    'AuditIPsecQuickMode'                  = '{0CCE9219-69AE-11D9-BED3-505054503030}' # IPsec Quick Mode
    'AuditIPsecExtendedMode'               = '{0CCE921A-69AE-11D9-BED3-505054503030}' # IPsec Extended Mode
    'AuditSpecialLogon'                    = '{0CCE921B-69AE-11D9-BED3-505054503030}' # Special Logon
    'AuditOtherLogonLogoffEvents'          = '{0CCE921C-69AE-11D9-BED3-505054503030}' # Other Logon/Logoff Events
    'AuditNetworkPolicyServer'             = '{0CCE921D-69AE-11D9-BED3-505054503030}' # Network Policy Server
    'AuditUserDeviceClaims'                = '{0CCE9254-69AE-11D9-BED3-505054503030}' # User/Device Claims (May need verification)

    'AuditFileShare'                       = '{0CCE9224-69AE-11D9-BED3-505054503030}' # File Share
    'AuditFilteringPlatformPacketDrop'     = '{0CCE9225-69AE-11D9-BED3-505054503030}' # Filtering Platform Packet Drop
    'AuditFilteringPlatformConnection'     = '{0CCE9226-69AE-11D9-BED3-505054503030}' # Filtering Platform Connection
    'AuditOtherObjectAccessEvents'         = '{0CCE9227-69AE-11D9-BED3-505054503030}' # Other Object Access Events
    'AuditDetailedFileShare'               = '{0CCE9252-69AE-11D9-BED3-505054503030}' # Detailed File Share
    'AuditRemovableStorage'                = '{0CCE9253-69AE-11D9-BED3-505054503030}' # Removable Storage
    'AuditCentralPolicyStaging'            = '{0CCE9255-69AE-11D9-BED3-505054503030}' # Central Policy Staging

    'AuditPolicyChange'                    = '{0CCE922F-69AE-11D9-BED3-505054503030}' # Audit Policy Change
    'AuditAuthenticationPolicyChange'      = '{0CCE9230-69AE-11D9-BED3-505054503030}' # Authentication Policy Change (KDC Policy Change in DC-LogMaster)
    'AuditAuthorizationPolicyChange'       = '{0CCE9231-69AE-11D9-BED3-505054503030}' # Authorization Policy Change

    'AuditUserAccountManagement'           = '{0CCE9235-69AE-11D9-BED3-505054503030}' # User Account Management
    'AuditComputerAccountManagement'       = '{0CCE9236-69AE-11D9-BED3-505054503030}' # Computer Account Management
    'AuditSecurityGroupManagement'         = '{0CCE9237-69AE-11D9-BED3-505054503030}' # Security Group Management
    'AuditDistributionGroupManagement'     = '{0CCE9238-69AE-11D9-BED3-505054503030}' # Distribution Group Management
    'AuditApplicationGroupManagement'      = '{0CCE9239-69AE-11D9-BED3-505054503030}' # Application Group Management
    'AuditOtherAccountManagementEvents'    = '{0CCE923A-69AE-11D9-BED3-505054503030}' # Other Account Management Events

    'AuditDirectoryServiceAccess'          = '{0CCE923B-69AE-11D9-BED3-505054503030}' # Directory Service Access
    'AuditDirectoryServiceChanges'         = '{0CCE923C-69AE-11D9-BED3-505054503030}' # Directory Service Changes
    'AuditDirectoryServiceReplication'     = '{0CCE923D-69AE-11D9-BED3-505054503030}' # Directory Service Replication
    'AuditDetailedDirectoryServiceReplication' = '{0CCE923E-69AE-11D9-BED3-505054503030}' # Detailed Directory Service Replication

    'AuditKerberosPreAuth'                 = '{0CCE923F-69AE-11D9-BED3-505054503030}' # Kerberos Authentication Service (PreAuth part)
    'AuditKerberosServiceTicketOperations' = '{0CCE9240-69AE-11D9-BED3-505054503030}' # Kerberos Service Ticket Operations
    'AuditCredentialValidation'            = '{0CCE9241-69AE-11D9-BED3-505054503030}' # Credential Validation
    'AuditKerberosAuthentication'          = '{0CCE9242-69AE-11D9-BED3-505054503030}' # Kerberos Authentication Service (TGT part)
    'AuditOtherAccountLogonEvents'         = '{0CCE9243-69AE-11D9-BED3-505054503030}' # Other Account Logon Events
    'AuditNTLMAuthentication'              = '{0CCE921E-69AE-11D9-BED3-505054503030}' # NTLM Authentication (Placeholder, often part of Other Account Logon)
    # Note: Some GUIDs from auditpol /get /category:* /r might not be in DC-LogMaster's original $AdvSubCatGuidMap if it was selective.
    # This map is expanded here to be more comprehensive for lookup based on GUIDs from auditpol output.
    # The 'RegistryPath' key is conceptual here, linking to Get-AuditMapping's structure.
}


function Get-AuditMapping {
    param([string]$LookupValue, [string]$LookupType = "RegistryPath") # LookupType can be "RegistryPath" or "SubCategoryGUID"

    # This mapping is based on DC-LogMaster's categories and event IDs.
    # It links a conceptual "RegistryPath" (used as a key in $AdvSubCatGuidMap for DC-LogMaster)
    # or a SubCategoryGUID directly to Event IDs.
    $mappings = @(
        @{Id=4624; RegistryPath='AuditLogon';                           SubCategoryName='Logon';                                  SubCategoryGUID='{0CCE9215-69AE-11D9-BED3-505054503030}'},
        @{Id=4625; RegistryPath='AuditLogoff';                          SubCategoryName='Logoff';                                 SubCategoryGUID='{0CCE9216-69AE-11D9-BED3-505054503030}'},
        @{Id=4626; RegistryPath='AuditUserAccountManagement';            SubCategoryName='User Account Management';                SubCategoryGUID='{0CCE9235-69AE-11D9-BED3-505054503030}'}, # Example: User Account Changed
        @{Id=4627; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Example: Group Member Added (Non-Interactive)

        @{Id=4768; RegistryPath='AuditKerberosAuthentication';          SubCategoryName='Kerberos Authentication Service';        SubCategoryGUID='{0CCE9242-69AE-11D9-BED3-505054503030}'}, # TGT Request
        @{Id=4769; RegistryPath='AuditKerberosServiceTicketOperations'; SubCategoryName='Kerberos Service Ticket Operations';     SubCategoryGUID='{0CCE9240-69AE-11D9-BED3-505054503030}'}, # Service Ticket Request
        @{Id=4771; RegistryPath='AuditKerberosPreAuth';                 SubCategoryName='Kerberos Authentication Service';        SubCategoryGUID='{0CCE923F-69AE-11D9-BED3-505054503030}'}, # Kerberos Pre-Auth Failed (Maps to KAS GUID in practice)
        @{Id=4772; RegistryPath='AuditKerberosAuthentication';          SubCategoryName='Kerberos Authentication Service';        SubCategoryGUID='{0CCE9242-69AE-11D9-BED3-505054503030}'}, # TGS Request Failed (falls under KAS)

        @{Id=4776; RegistryPath='AuditCredentialValidation';              SubCategoryName='Credential Validation';                  SubCategoryGUID='{0CCE9241-69AE-11D9-BED3-505054503030}'}, # NTLM Authentication Success (Credential Validation)
        @{Id=4777; RegistryPath='AuditCredentialValidation';              SubCategoryName='Credential Validation';                  SubCategoryGUID='{0CCE9241-69AE-11D9-BED3-505054503030}'}, # NTLM Auth Failure (falls under Credential Validation for some views)

        @{Id=4720; RegistryPath='AuditUserAccountManagement';            SubCategoryName='User Account Management';                SubCategoryGUID='{0CCE9235-69AE-11D9-BED3-505054503030}'}, # User Created
        @{Id=4722; RegistryPath='AuditUserAccountManagement';            SubCategoryName='User Account Management';                SubCategoryGUID='{0CCE9235-69AE-11D9-BED3-505054503030}'}, # User Enabled
        @{Id=4724; RegistryPath='AuditUserAccountManagement';            SubCategoryName='User Account Management';                SubCategoryGUID='{0CCE9235-69AE-11D9-BED3-505054503030}'}, # Password Reset
        @{Id=4725; RegistryPath='AuditUserAccountManagement';            SubCategoryName='User Account Management';                SubCategoryGUID='{0CCE9235-69AE-11D9-BED3-505054503030}'}, # User Disabled
        @{Id=4726; RegistryPath='AuditUserAccountManagement';            SubCategoryName='User Account Management';                SubCategoryGUID='{0CCE9235-69AE-11D9-BED3-505054503030}'}, # User Deleted

        @{Id=4727; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Group Created
        @{Id=4728; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Member Added to Global Group
        @{Id=4729; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Member Removed from Global Group
        @{Id=4730; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Global Group Deleted
        @{Id=4731; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Local Group Created
        @{Id=4732; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Member Added to Local Group
        @{Id=4733; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Member Removed from Local Group
        @{Id=4734; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Local Group Deleted
        @{Id=4735; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Local Group Changed
        @{Id=4737; RegistryPath='AuditSecurityGroupManagement';          SubCategoryName='Security Group Management';              SubCategoryGUID='{0CCE9237-69AE-11D9-BED3-505054503030}'}, # Global Group Changed

        @{Id=4754; RegistryPath='AuditDistributionGroupManagement';      SubCategoryName='Distribution Group Management';          SubCategoryGUID='{0CCE9238-69AE-11D9-BED3-505054503030}'}, # Universal Group Created
        @{Id=4755; RegistryPath='AuditDistributionGroupManagement';      SubCategoryName='Distribution Group Management';          SubCategoryGUID='{0CCE9238-69AE-11D9-BED3-505054503030}'}, # Universal Group Changed
        @{Id=4756; RegistryPath='AuditDistributionGroupManagement';      SubCategoryName='Distribution Group Management';          SubCategoryGUID='{0CCE9238-69AE-11D9-BED3-505054503030}'}, # Member Added to Universal Group
        @{Id=4757; RegistryPath='AuditDistributionGroupManagement';      SubCategoryName='Distribution Group Management';          SubCategoryGUID='{0CCE9238-69AE-11D9-BED3-505054503030}'}, # Member Removed from Universal Group
        @{Id=4758; RegistryPath='AuditDistributionGroupManagement';      SubCategoryName='Distribution Group Management';          SubCategoryGUID='{0CCE9238-69AE-11D9-BED3-505054503030}'}, # Universal Group Deleted

        @{Id=5136; RegistryPath='AuditDirectoryServiceChanges';         SubCategoryName='Directory Service Changes';              SubCategoryGUID='{0CCE923C-69AE-11D9-BED3-505054503030}'}, # DS Modify
        @{Id=5137; RegistryPath='AuditDirectoryServiceChanges';         SubCategoryName='Directory Service Changes';              SubCategoryGUID='{0CCE923C-69AE-11D9-BED3-505054503030}'}, # DS Create
        @{Id=5138; RegistryPath='AuditDirectoryServiceChanges';         SubCategoryName='Directory Service Changes';              SubCategoryGUID='{0CCE923C-69AE-11D9-BED3-505054503030}'}, # DS Delete
        @{Id=4662; RegistryPath='AuditDirectoryServiceAccess';          SubCategoryName='Directory Service Access';               SubCategoryGUID='{0CCE923B-69AE-11D9-BED3-505054503030}'}, # DS Access
        @{Id=4663; RegistryPath='AuditDirectoryServiceChanges';         SubCategoryName='Directory Service Changes';              SubCategoryGUID='{0CCE923C-69AE-11D9-BED3-505054503030}'}, # DS Changes (generic)

        @{Id=6400; RegistryPath='AuditAuthenticationPolicyChange';      SubCategoryName='Authentication Policy Change';           SubCategoryGUID='{0CCE9230-69AE-11D9-BED3-505054503030}'}, # KDC Policy Change
        @{Id=6401; RegistryPath='AuditAuthenticationPolicyChange';      SubCategoryName='Authentication Policy Change';           SubCategoryGUID='{0CCE9230-69AE-11D9-BED3-505054503030}'}, # KDC Service Start

        @{Id=4719; RegistryPath='AuditPolicyChange';                    SubCategoryName='Audit Policy Change';                    SubCategoryGUID='{0CCE922F-69AE-11D9-BED3-505054503030}'}  # Audit Policy Change
    )

    if ($LookupType -eq "RegistryPath") {
        return $mappings | Where-Object { $_.RegistryPath -eq $LookupValue }
    } elseif ($LookupType -eq "SubCategoryGUID") {
        return $mappings | Where-Object { $_.SubCategoryGUID -eq $LookupValue }
    } else { # Fallback or for EventID lookup
        return $mappings | Where-Object { $_.Id -eq $LookupValue }
    }
}


# --- END CORE AUDIT POLICY FUNCTIONS ---

function Show-DetailedEffectivePolicy {
    [CmdletBinding()]
    param()

    Write-Log -Message "Displaying detailed effective audit policy settings." -Level INFO

    $detailedPolicies = Get-EffectiveAuditPolicyDetailed

    if ($detailedPolicies) {
        Write-Host "`n--- Detailed Audit Policy Configuration (Effective Local Settings from 'auditpol /get /category:* /r') ---" -ForegroundColor Cyan

        foreach ($policyEntry in $detailedPolicies) {
            $subcategoryName = $policyEntry.Subcategory.Trim()
            $subcategoryGuid = $policyEntry."Subcategory GUID".Trim() # Property name has a space
            $inclusionSetting = $policyEntry."Inclusion Setting".Trim()

            $status = "Not Configured"
            if ($inclusionSetting -eq "Success and Failure") { $status = "Success and Failure" }
            elseif ($inclusionSetting -eq "Success") { $status = "Success" }
            elseif ($inclusionSetting -eq "Failure") { $status = "Failure" }
            elseif ($inclusionSetting -eq "No Auditing") { $status = "No Auditing" }

            # Attempt to find associated Event IDs
            $associatedEventIDs = @()
            # Lookup via GUID directly in Get-AuditMapping
            $mappingsByGuid = Get-AuditMapping -LookupValue $subcategoryGuid -LookupType "SubCategoryGUID"
            if ($mappingsByGuid) {
                $associatedEventIDs += $mappingsByGuid.Id
            }

            # Fallback or supplement: Lookup via conceptual RegistryPath if direct GUID match is not exhaustive
            # This requires finding the RegistryPath key from the $AdvSubCatGuidMap where value is $subcategoryGuid
            if ($associatedEventIDs.Count -eq 0) { # Only if no IDs found by direct GUID match, or to be more exhaustive
                foreach ($key in $AdvSubCatGuidMap.Keys) {
                    if ($AdvSubCatGuidMap[$key] -eq $subcategoryGuid) {
                        $mappingsByRegPath = Get-AuditMapping -LookupValue $key -LookupType "RegistryPath"
                        if ($mappingsByRegPath) {
                            $associatedEventIDs += $mappingsByRegPath.Id
                        }
                        break # Assuming one RegistryPath per GUID in this context
                    }
                }
            }
            $uniqueEventIDs = $associatedEventIDs | Sort-Object -Unique
            $eventIDsString = if ($uniqueEventIDs.Count -gt 0) { " (EventIDs: $($uniqueEventIDs -join ', '))" } else { "" }

            Write-Host ("  Subcategory: {0,-45} Status: {1,-20} GUID: {2}{3}" -f $subcategoryName, $status, $subcategoryGuid, $eventIDsString)
        }
        Write-Log -Message "Displayed detailed audit policy settings with Event ID correlation." -Level INFO

        Write-Warning "IMPORTANT: The settings displayed above are the *effective local audit policies* currently active on this machine. In a domain environment, these settings are typically managed and enforced by Group Policy Objects (GPOs). After a 'gpupdate', these settings will reflect the GPO configuration."

    } else {
        Write-Log -Message "Could not retrieve or parse detailed audit policy from auditpol." -Level ERROR
        Write-Error "Failed to retrieve or parse detailed audit policy. Check log for details."
    }
}

function Show-Help {
    # Help output for this specific script
    Write-Host "Usage: .\View-DCEffectiveAuditPolicy.ps1 [-LogFilePath <path>]" -ForegroundColor Cyan
    Write-Host "Version: $ScriptVersion"
    Write-Host "Displays the current effective advanced audit policy settings with associated Event IDs."
    Write-Host "  -h, --help                 Show this help message."
    Write-Host "  -LogFilePath <path>        Specify log file path (default: .\View-DCEffectiveAuditPolicy.log)."
}

# Main script logic
Write-Log -Message "View-DCEffectiveAuditPolicy.ps1 - Version $ScriptVersion - Started."
Write-Log -Message "Log file: $LogFilePath" -Level INFO
Write-Log -Message "Command line arguments: $($MyInvocation.Line)" -Level INFO

if ($Help) {
    Show-Help
    Write-Log -Message "Displayed help information." -Level INFO
} else {
    # Default action
    Show-DetailedEffectivePolicy
}

Write-Log -Message "View-DCEffectiveAuditPolicy.ps1 - Finished."

# End of script
