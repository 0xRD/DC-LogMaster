<#
.SYNOPSIS
    DC-LogMaster: Manage and strengthen Domain Controller audit settings
.DESCRIPTION
    Configures advanced audit policy on a Domain Controller using auditpol with GUIDs,
    eliminating language/localization issues. Show-Current uses auditpol exclusively.
.TO DO
    Ensure the GUIDs in $AdvSubCatGuidMap match your environment.
    To export all subcategory GUIDs, run:
        auditpol /list /subcategory:* /v | Out-File C:\temp\auditpol_subcats.txt -Encoding UTF8
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [alias('h','?')][switch] $Help,
    [switch]               $ShowCurrent,
    [switch]               $ShowAvailable,
    [string[]]             $Enable,
    [string[]]             $Disable,
    [string]               $LogFilePath = ".\DC-LogMaster.log", # Parameter for log file path
    [string]               $ExportPolicy = "$PWD\DC-LogMaster_AuditPolicyExport.csv", # Parameter to specify path for exporting audit policy, with default
    [string]               $ImportPolicy  # Parameter to specify path for importing audit policy
)

#Requires -Modules GroupPolicy, ActiveDirectory

# Global Variables
$ScriptVersion = "1.1.0"
$AdvancedAuditPolicyRegistryPath = "SOFTWARE\Policies\Microsoft\Windows\Audit"
# $LogFile variable is now replaced by $LogFilePath parameter with adefault value

# --- BEGIN HELPER FUNCTIONS ---
function Test-ParentDirectoryWriteable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $parentDir = Split-Path -Path $FilePath -Parent
    if ($parentDir -and (-not (Test-Path -Path $parentDir -PathType Container))) {
        Write-Log -Message "Parent directory '$parentDir' for file '$FilePath' does not exist." -Level ERROR
        return $false
    }
    # Attempt to create a temporary file in the parent directory to check writability
    # This is a more robust check but can be intrusive. For now, just check existence.
    # If parentDir is empty (meaning $FilePath is just a filename), assume current dir is writable.
    if ($parentDir) {
        try {
            $tempFile = Join-Path -Path $parentDir -ChildPath ([System.Guid]::NewGuid().ToString() + ".tmp")
            New-Item -Path $tempFile -ItemType File -ErrorAction Stop | Out-Null
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Parent directory '$parentDir' for file '$FilePath' is not writeable. Error: $($_.Exception.Message)" -Level ERROR
            return $false
        }
    } elseif (-not $FilePath.Contains("\") -and -not $FilePath.Contains("/")) {
        # FilePath is a relative filename, check current directory writability
        try {
            $tempFile = Join-Path -Path (Get-Location) -ChildPath ([System.Guid]::NewGuid().ToString() + ".tmp")
            New-Item -Path $tempFile -ItemType File -ErrorAction Stop | Out-Null
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        } catch {
             Write-Log -Message "Current directory '$(Get-Location)' for file '$FilePath' is not writeable. Error: $($_.Exception.Message)" -Level ERROR
            return $false
        }
    } # Else, $FilePath is a full path to a file in the root, e.g. C:\file.log - Test-Path handles this.

    return $true
}
# --- END HELPER FUNCTIONS ---

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
        # If logging fails, we might want to stop the script or notify in a more aggressive way.
        # For now, just write an error to console.
    }

    switch ($Level) {
        "INFO"  { Write-Host $logEntry }
        "WARN"  { Write-Warning $logEntry } # Write-Warning already includes "WARNING: "
        "ERROR" { Write-Error $logEntry }   # Write-Error already includes error details
        "DEBUG" { Write-Debug $logEntry }
        default { Write-Host $logEntry }
    }
}
# --- END LOGGING FUNCTION ---

# --- BEGIN GPO DETECTION FUNCTIONS ---

function Get-AdvancedAuditPolicyGPOs {
    [CmdletBinding()]
    param()

    Write-Log -Message "Attempting to detect GPOs configuring Advanced Audit Policy..." -Level INFO

    if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
        Write-Log -Message "GroupPolicy PowerShell module is not available. Skipping GPO detection." -Level WARN
        return $null
    }
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        Write-Log -Message "ActiveDirectory PowerShell module is not available. Skipping GPO detection (needed to find DC's OU)." -Level WARN
        return $null
    }

    try {
        Write-Log -Message "GPO Debug: Attempting to discover PrimaryDC information." -Level DEBUG
        $discoveredDCs = Get-ADDomainController -Discover -Service PrimaryDC -ErrorAction SilentlyContinue

        if (-not $discoveredDCs) {
            Write-Log -Message "GPO Debug: Get-ADDomainController -Discover -Service PrimaryDC failed to return any objects." -Level WARN
            Write-Log -Message "Could not discover PrimaryDC. Ensure this script is run on a domain-joined machine, preferably a DC. Skipping GPO detection." -Level WARN
            return $null
        }

        # Ensure we are working with a single DC info object
        $dcInfo = $discoveredDCs | Select-Object -First 1

        if (-not $dcInfo -or -not $dcInfo.HostName) {
            Write-Log -Message "GPO Debug: Discovered DC object or its HostName property is null/empty." -Level WARN
             Write-Log -Message "Could not reliably determine DC HostName. Skipping GPO detection." -Level WARN
            return $null
        }

        $dcHostName = $dcInfo.HostName
        # HostName from Get-ADDomainController should be a string. If it's a collection, it's unexpected.
        # However, the error message implies something became a collection.
        # Forcing it to string here if it was some other type from pipeline.
        if ($dcHostName -isnot [string]) {
            Write-Log -Message "GPO Debug: dcInfo.HostName was not a string (Type: $($dcHostName.GetType().FullName)). Forcing to string. Value: $dcHostName" -Level WARN
            $dcHostName = [string]$dcHostName
        }

        Write-Log -Message "GPO Debug: Using DC HostName '$dcHostName' to get ADComputer object." -Level DEBUG
        # If dcHostName appears to be an FQDN (e.g., forest.domain.host), try using just the host part for Get-ADComputer
        $identityForADComputer = $dcHostName
        if ($dcHostName -like "*.*.*") { # Simple check for multiple dots, common in Forest.Domain.Host
            $identityForADComputer = ($dcHostName -split '\.')[0] # Try with the first part (NetBIOS name)
            Write-Log -Message "GPO Debug: dcHostName '$dcHostName' appears to be complex. Using '$identityForADComputer' as identity for Get-ADComputer." -Level DEBUG
        }

        # Fallback to $env:COMPUTERNAME if $identityForADComputer is problematic or for robustness on the DC itself
        # Or, if Get-ADComputer fails, we might rely more on Get-ADDomain for domain info.
        $currentDCComputer = Get-ADComputer -Identity $identityForADComputer -Properties DistinguishedName -ErrorAction SilentlyContinue

        if (-not $currentDCComputer) {
            Write-Log -Message "GPO Debug: Get-ADComputer failed for identity '$identityForADComputer'. Trying with `$env:COMPUTERNAME ('$($env:COMPUTERNAME)')." -Level WARN
            $currentDCComputer = Get-ADComputer -Identity $env:COMPUTERNAME -Properties DistinguishedName -ErrorAction SilentlyContinue
            if (-not $currentDCComputer) {
                Write-Log -Message "GPO Debug: Get-ADComputer also failed for identity '$($env:COMPUTERNAME)'." -Level WARN
                Write-Log -Message "Could not reliably retrieve AD object for the current DC. Skipping GPO detection." -Level ERROR
                return $null
            }
        }
        Write-Log -Message "GPO Debug: Successfully retrieved ADComputer object. DN: $($currentDCComputer.DistinguishedName)" -Level DEBUG

        # For Get-GPRegistryValue -Domain, use Get-ADDomain for reliability
        $currentDomainInfo = Get-ADDomain -ErrorAction SilentlyContinue
        if (-not $currentDomainInfo) {
            Write-Log -Message "GPO Debug: Get-ADDomain failed. Cannot reliably determine domain FQDN for GPO analysis." -Level ERROR
            return $null
        }
        $reliableDomainFQDN = $currentDomainInfo.DNSRoot
        Write-Log -Message "GPO Debug: Using reliable domain FQDN '$reliableDomainFQDN' for GPO analysis." -Level DEBUG

        $dcDN = $currentDCComputer.DistinguishedName
        Write-Log -Message "GPO Debug: Value of `$dcDN before Split-Path: '$($dcDN)' (Type: $($dcDN.GetType().FullName))" -Level DEBUG

        # Attempt to ensure dcDN is a clean string for Split-Path
        $cleanDcDN = [string]$dcDN.Trim()
        Write-Log -Message "GPO Debug: Value of `$cleanDcDN after Trim: '$($cleanDcDN)'" -Level DEBUG

        $dcParentContainerDN = Split-Path -Path $cleanDcDN -Parent
        Write-Log -Message "GPO Debug: Value of `$dcParentContainerDN after Split-Path: '$($dcParentContainerDN)'" -Level DEBUG

        if (-not $dcParentContainerDN) {
             Write-Log -Message "Could not determine parent container DN for DC from original DN '$dcDN' (cleaned as '$cleanDcDN'). This is unexpected. Skipping GPO check for specific container." -Level WARN
        }

        $gpoLinksToProcess = [System.Collections.Generic.List[Microsoft.GroupPolicy.GpoLink]]::new()
        $checkedTargets = [System.Collections.Generic.List[string]]::new()

        # Attempt to get GPOs from DC's specific container first
        if ($dcParentContainerDN) {
            Write-Log -Message "Checking GPOs linked to DC's container: $dcParentContainerDN (DC: $($env:COMPUTERNAME))" -Level INFO
            $gpInheritanceContainer = Get-GPInheritance -Target $dcParentContainerDN -Domain $reliableDomainFQDN -ErrorAction SilentlyContinue
            if ($gpInheritanceContainer) {
                $gpoLinksToProcess.AddRange($gpInheritanceContainer.GpoLinks)
                $checkedTargets.Add($dcParentContainerDN)
            } else {
                Write-Log -Message "Could not retrieve GPO inheritance for '$dcParentContainerDN'. This might happen due to permissions or if it's a non-OU container not directly queryable this way for inheritance details." -Level WARN
            }
        }

        # Always check domain-level GPOs
        $domainDN = $currentDomainInfo.DistinguishedName # Use DN from Get-ADDomain
        if ($domainDN -and (-not $checkedTargets.Contains($domainDN))) {
            Write-Log -Message "Checking GPOs linked to domain: $domainDN" -Level INFO
            $gpInheritanceDomain = Get-GPInheritance -Target $domainDN -Domain $reliableDomainFQDN -ErrorAction SilentlyContinue
            if ($gpInheritanceDomain) {
                $gpoLinksToProcess.AddRange($gpInheritanceDomain.GpoLinks)
                $checkedTargets.Add($domainDN)
            } else {
                 Write-Log -Message "Could not retrieve GPO inheritance for domain '$domainDN'." -Level WARN
            }
        }

        if ($gpoLinksToProcess.Count -eq 0) {
            Write-Log -Message "No GPO links found for checked targets: $($checkedTargets -join '; '). No GPOs to analyze." -Level INFO
            return $null
        }

        $configuringGPOs = [System.Collections.Generic.List[string]]::new()
        $uniqueGpoLinks = $gpoLinksToProcess | Sort-Object -Property Id -Unique


        foreach ($gpoLink in $uniqueGpoLinks) {
            $gpoName = $gpoLink.DisplayName
            Write-Log -Message "Analyzing GPO: '$gpoName' (ID: $($gpoLink.Id)) linked to '$($gpoLink.SOMPath)'" -Level DEBUG
            try {
                # Use reliableDomainFQDN for the -Domain parameter
                $regSettings = Get-GPRegistryValue -Name $gpoName -Domain $reliableDomainFQDN -Key $AdvancedAuditPolicyRegistryPath -ErrorAction SilentlyContinue
                if ($regSettings -and $regSettings.Count -gt 0) {
                    Write-Log -Message "Found potential Advanced Audit Policy settings in GPO: '$gpoName' (ID: $($gpoLink.Id))" -Level INFO
                    if (-not $configuringGPOs.Contains($gpoName)) {
                        $configuringGPOs.Add($gpoName)
                    }
                }
            } catch {
                $errMsg = $_.Exception.Message
                if ($errMsg -like "*The following key is not valid for a Group Policy registry setting*" -or $errMsg -like "*Cannot find the registry key*") {
                    Write-Log -Message "GPO Analysis: GPO '$gpoName' (ID: $($gpoLink.Id)) does not appear to configure Advanced Audit Policy via the specific registry path '$AdvancedAuditPolicyRegistryPath'. This is expected if policies are set via audit.csv. Message: $errMsg" -Level DEBUG
                } else {
                    # Log other errors as warnings
                    Write-Log -Message "Could not fully analyze GPO '$gpoName' (ID: $($gpoLink.Id)) for registry settings at '$AdvancedAuditPolicyRegistryPath'. Error: $errMsg. This GPO might be corrupt, inaccessible, or the domain '$reliableDomainFQDN' might be incorrect for this GPO context." -Level WARN
                }
            }
        }

        if ($configuringGPOs.Count -gt 0) {
            Write-Log -Message "Detected GPOs potentially configuring Advanced Audit Policy: $($configuringGPOs -join ', ')" -Level INFO
            return $configuringGPOs
        } else {
            # Corrected the target logging string to use joined $checkedTargets
            Write-Log -Message "No GPOs found explicitly configuring Advanced Audit Policy settings via registry keys at '$AdvancedAuditPolicyRegistryPath' for checked targets: $($checkedTargets -join '; '). However, GPOs can enforce these settings in other ways or settings may be in unreadable GPOs." -Level INFO
            return $null
        }
    } catch {
        Write-Log -Message "An error occurred during GPO detection: $($_.Exception.Message). ScriptStackTrace: $($_.ScriptStackTrace)" -Level ERROR
        return $null
    }
}

# --- END GPO DETECTION FUNCTIONS ---

# --- BEGIN EXPORT/IMPORT FUNCTIONS ---

function Export-DCAuditPolicy {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    Write-Log -Message "Attempting to export current audit policy to '$FilePath'." -Level INFO

    if ($PSCmdlet.ShouldProcess("'$FilePath'", "Export audit policy using auditpol /backup")) {
        if (Test-Path -Path $FilePath -PathType Leaf) {
            Write-Log -Message "Export file '$FilePath' already exists. Attempting to delete it before export." -Level INFO
            Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue # SilentlyContinue as auditpol might overwrite anyway
            if (Test-Path -Path $FilePath -PathType Leaf) {
                Write-Log -Message "Failed to delete existing export file '$FilePath'. Auditpol will attempt to overwrite." -Level WARN
            } else {
                Write-Log -Message "Successfully deleted existing export file '$FilePath'." -Level INFO
            }
        }

        auditpol /backup /file:"$FilePath"
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Message "Audit policy successfully exported to '$FilePath'." -Level INFO
            Write-Host "Audit policy successfully exported to '$FilePath'." -ForegroundColor Green
        } else {
            $errorMessage = "Failed to export audit policy using 'auditpol /backup /file:`"$FilePath`"'. Exit code: $LASTEXITCODE."
            if ($LASTEXITCODE -eq 80) {
                $errorMessage += " (Exit code 80 often indicates issues like: file locked, path not found, permission denied, or corrupted target file if it existed.)"
            }
            Write-Log -Message $errorMessage -Level ERROR
        }
    } else {
        Write-Log -Message "Skipped (ShouldProcess): Export audit policy to '$FilePath'." -Level INFO
    }
}

function Import-DCAuditPolicy {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    Write-Log -Message "Attempting to import audit policy from '$FilePath'." -Level INFO

    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        Write-Log -Message "Import file '$FilePath' not found or is not a file. Aborting import." -Level ERROR
        return
    }

    if ($PSCmdlet.ShouldProcess("'$FilePath'", "Import audit policy using auditpol /restore")) {
        # GPO Warning specific to import
        if ($detectedGPOs) { # Relies on $detectedGPOs being populated from the main script block
            $gpoWarningMsg = "CRITICAL: One or more GPOs appear to be configuring Advanced Audit Policy: $($detectedGPOs -join ', '). Importing a local policy from '$FilePath' will likely be overridden by these GPOs and may not persist or take effect as expected. It is strongly recommended to manage these audit settings via the identified GPO(s)."
            Write-Log -Message $gpoWarningMsg -Level WARN
            Write-Warning $gpoWarningMsg
            # Optionally, add a confirmation prompt here if running interactively
            # if ($Host.UI.RawUI.KeyAvailable -and ($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").VirtualKeyCode -ne 13) ) { # Example: Abort if not Enter
            #    Write-Log -Message "User aborted import due to GPO warning." -Level INFO; return
            # }
        }

        auditpol /restore /file:"$FilePath"
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Message "Audit policy successfully imported from '$FilePath'." -Level INFO
            Write-Host "Audit policy successfully imported from '$FilePath'." -ForegroundColor Green
            Write-Log -Message "A system reboot might be required for all imported audit policy settings to take full effect." -Level WARN
            Write-Warning "A system reboot might be required for all imported audit policy settings to take full effect."
        } else {
            Write-Log -Message "Failed to import audit policy using 'auditpol /restore /file:`"$FilePath`"'. Exit code: $LASTEXITCODE." -Level ERROR
        }
    } else {
        Write-Log -Message "Skipped (ShouldProcess): Import audit policy from '$FilePath'." -Level INFO
    }
}

# --- END EXPORT/IMPORT FUNCTIONS ---

# Global GUID map: RegistryPath -> Subcategory GUID (from auditpol export)
$AdvSubCatGuidMap = @{
    'AuditLogon'                           = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'AuditLogoff'                          = '{0CCE9216-69AE-11D9-BED3-505054503030}'
    'AuditKerberosAuthentication'          = '{0CCE9242-69AE-11D9-BED3-505054503030}'
    'AuditKerberosServiceTicketOperations' = '{0CCE9240-69AE-11D9-BED3-505054503030}'
    'AuditKerberosPreAuth'                 = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    'AuditNTLMAuthentication'              = '{0CCE921E-69AE-11D9-BED3-505054503030}'
    'AuditUserAccountManagement'           = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'AuditSecurityGroupManagement'         = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'AuditDistributionGroupManagement'     = '{0CCE9238-69AE-11D9-BED3-505054503030}'
    'AuditDirectoryServiceChanges'         = '{0CCE923C-69AE-11D9-BED3-505054503030}'
    'AuditDirectoryServiceAccess'          = '{0CCE923B-69AE-11D9-BED3-505054503030}'
    'AuditKDCPolicyChange'                 = '{0CCE9230-69AE-11D9-BED3-505054503030}'
    'AuditPolicyChange'                    = '{0CCE922F-69AE-11D9-BED3-505054503030}'
}

function Get-Categories {
    return @{
        low           = @{ IDs = @(4624,4625); Color = 'Green';   LogImpact = 'Low' }
        medium        = @{ IDs = @(4768,4769,4771,4776); Color = 'Yellow';  LogImpact = 'Medium' }
        high          = @{ IDs = @(5136,5137,5138,6400,6401,4662,4663); Color = 'Red'; LogImpact = 'High (Potentially Noisy)' }
        accounts      = @{ IDs = @(4720,4722,4724,4725,4726); Color = 'Magenta'; LogImpact = 'Medium' }
        groups        = @{ IDs = @(4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758); Color = 'Cyan'; LogImpact = 'Medium' }
        kerberos      = @{ IDs = @(4768,4769,4771,4772,4776,4777); Color = 'Yellow';  LogImpact = 'Medium to High (Depends on activity)' }
        objectaccess  = @{ IDs = @(4662,4663); Color = 'Blue';    LogImpact = 'Very High (Use with targeted SACLs)' }
        policychange  = @{ IDs = @(4719); Color = 'Magenta'; LogImpact = 'Low to Medium (Important for security)' }
    }
}

function Show-Help {
    # Help output doesn't need to be logged, it's user-facing console output.
    Write-Host 'Usage: .\DC-LogMaster.ps1 [options]' -ForegroundColor Cyan
    Write-Host "Version: $ScriptVersion"
    Write-Host '  -h, --help                 Show this help message'
    Write-Host '  -ShowCurrent               Display current auditpol settings'
    Write-Host '  -ShowAvailable             List categories and their Event IDs'
    Write-Host '  -Enable <cats>             Enable categories (use "all" for all)'
    Write-Host '  -Disable <cats>            Disable categories (use "all" for all)'
    Write-Host '  -ExportPolicy <filepath>   Export current audit policy to a file'
    Write-Host '  -ImportPolicy <filepath>   Import audit policy from a file'
    Write-Host '  -LogFilePath <path>        Specify log file path (default: .\DC-LogMaster.log)' -ForegroundColor DarkGray
    Write-Host 'Categories - verbosity & detection focus:' -ForegroundColor Yellow
    $categories = Get-Categories
    Write-Host ("  low                   -> low verbosity (essential events: {0})" -f ($categories.low.IDs -join ',')) -ForegroundColor Green
    Write-Host ("  medium                -> medium verbosity (additional events: {0})" -f ($categories.medium.IDs -join ',')) -ForegroundColor Yellow
    Write-Host ("  high               -> high verbosity (detailed + object access: {0})" -f ($categories.high.IDs -join ',')) -ForegroundColor Red
    Write-Host '  accounts           -> account management events' -ForegroundColor Magenta
    Write-Host '  groups             -> security group management events' -ForegroundColor Cyan
    Write-Host '  kerberos           -> Kerberos authentication events' -ForegroundColor Yellow
    Write-Host '  objectaccess       -> directory service access (4662,4663)' -ForegroundColor Blue
    Write-Host '  policychange       -> audit policy change events (4719)' -ForegroundColor Magenta
}

function Show-Available {
    Write-Log -Message "Displaying available categories and Event IDs." -Level INFO
    # Console output for user is fine here, logging the action is key.
    Write-Host 'Available categories and Event IDs:' -ForegroundColor Cyan
    $cats = Get-Categories
    foreach ($category in $cats.Keys) {
        $desc = switch ($category) {
            'low'          {'(low verbosity)'}
            'medium'       {'(medium verbosity)'}
            'high'         {'(high verbosity + access)'}
            'accounts'     {'(account management)'}
            'groups'       {'(security group management)'}
            'kerberos'     {'(Kerberos)'}
            'objectaccess' {'(object access)'}
            'policychange' {'(audit policy change)'}
            default        {''}
        }
        # Adjusting formatting to include LogImpact
        # Old format: "  {0,-12} {1,-20} -> {2}"
        # New format: "  Category: {0,-12} Desc: {1,-28} Impact: {2,-15} EventIDs: {3}"
        $logImpact = $cats[$category].LogImpact
        Write-Host ("  {0,-12} {1,-28} Impact: {2,-35} EventIDs: {3}" -f $category, $desc, $logImpact, ($cats[$category].IDs -join ',')) -ForegroundColor $cats[$category].Color
    }
    Write-Host "`nLog Impact Levels:" -ForegroundColor Yellow
    Write-Host "  Low: Minimal event log noise, typically essential security events."
    Write-Host "  Medium: Moderate event volume, useful for broader monitoring."
    Write-Host "  High (Potentially Noisy): Significant event volume, may require tuning or specific focus."
    Write-Host "  Medium to High (Depends on activity): Volume varies with system activity."
    Write-Host "  Very High (Use with targeted SACLs): Can generate extreme volume if not carefully configured (e.g., Object Access)."
    Write-Host "  Low to Medium (Important for security): Important events, volume usually manageable."

}

function Get-SubcategoryStatus {
    param([string]$Guid)
    # This function is internal; logging individual checks might be too verbose.
    # Consider adding -Level DEBUG if needed.
    $output = auditpol /get /subcategory:"$Guid" 2>&1
    # Check $LASTEXITCODE here too for auditpol robustness
    if ($LASTEXITCODE -ne 0) {
        Write-Log -Message "auditpol /get /subcategory:$Guid failed. Exit code: $LASTEXITCODE. Output: $output" -Level WARN
        return "Error" # Or some other indicator of failure
    }
    if ($output -match 'Success and Failure') { return 'SuccessAndFailure' }
    elseif ($output -match '\bSuccess\b') { return 'Success' }
    elseif ($output -match '\bFailure\b') { return 'Failure' }
    elseif ($output -match 'No Auditing') { return 'No Auditing' } # Auditpol can output this
    else { return 'NotConfigured' } # Default or if output is unexpected
}

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

        # The output of auditpol /r is CSV-like but might have header/footer info or be inconsistent.
        # We need to parse it carefully. It typically has "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting"
        # Let's convert it to PSObjects. Skip the first line if it's "Command execution complete." or similar.
        # The actual CSV data starts after a line like "Machine Name,Policy Target,..."

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

        if ($csvDataLines.Count -lt 2) { # Need at least header + 1 data line
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


function Show-Current {
    Write-Log -Message "Displaying current audit settings." -Level INFO

    # Existing GPO warning if specific registry-based GPOs were detected
    if ($PSBoundParameters.ContainsKey('ShowCurrent') -and $detectedGPOs) { # Check if $detectedGPOs is from a run where ShowCurrent was the operation
        Write-Log -Message "Warning user that displayed local settings from ShowCurrent may be overridden by GPOs: $($detectedGPOs -join ', ')" -Level WARN
        Write-Warning "GPO DETECTION: This script found indications that the following GPOs might be configuring Advanced Audit Policy via specific registry keys: $($detectedGPOs -join ', '). Settings from these GPOs will override local settings."
    }

    $detailedPolicies = Get-EffectiveAuditPolicyDetailed

    if ($detailedPolicies) {
        Write-Host "`n--- Detailed Audit Policy Configuration (Effective Local Settings from 'auditpol /get /category:* /r') ---" -ForegroundColor Cyan
        $detailedPolicies | ForEach-Object {
            $inclusion = $_."Inclusion Setting".Trim()
            $subcategoryName = $_.Subcategory.Trim()
            $status = "Not Configured"
            if ($inclusion -eq "Success and Failure") { $status = "Success and Failure" }
            elseif ($inclusion -eq "Success") { $status = "Success" }
            elseif ($inclusion -eq "Failure") { $status = "Failure" }
            elseif ($inclusion -eq "No Auditing") { $status = "No Auditing" }

            Write-Host ("  Subcategory: {0,-45} Status: {1}" -f $subcategoryName, $status)
        }
        Write-Log -Message "Displayed detailed audit policy settings (effective local settings)." -Level INFO

        Write-Warning "IMPORTANT: The settings displayed above are the *effective local audit policies* currently active on this machine. In a domain environment, these settings are typically managed and enforced by Group Policy Objects (GPOs). After a 'gpupdate', these settings will reflect the GPO configuration. This script's GPO detection (which checks for specific registry keys) may not identify all GPO configurations, especially those set via 'audit.csv' files within GPOs (the standard for Advanced Audit Policy)."

    } else {
        Write-Log -Message "Could not retrieve detailed audit policy. Falling back to script-defined category check." -Level WARN
        Write-Warning "Could not retrieve detailed audit policy using 'auditpol /get /category:* /r'. Falling back to checking script-defined categories only. Effective GPO settings may not be fully represented."

        Write-Host "`n--- Audit Policy Configuration (based on script categories) ---" -ForegroundColor Cyan
        $cats = Get-Categories
        foreach ($categoryName in $cats.Keys) {
            Write-Host "`n$($categoryName):" -ForegroundColor $cats[$categoryName].Color
            foreach ($id in $cats[$categoryName].IDs) {
                $map = Get-AuditMapping -EventId $id
                if (-not $map) {
                    Write-Log -Message "No audit mapping found for Event ID $id in category $categoryName." -Level WARN
                    continue
                }
                if (-not $AdvSubCatGuidMap.ContainsKey($map.RegistryPath)) {
                     Write-Log -Message "GUID not found in AdvSubCatGuidMap for RegistryPath '$($map.RegistryPath)' (Event ID $id)." -Level WARN
                    continue
                }
                $guid = $AdvSubCatGuidMap[$map.RegistryPath]
                $status = Get-SubcategoryStatus -Guid $guid
                Write-Host ("  EventID {0} ({1}): {2}" -f $id, $map.SubCategory, $status)
            }
        }
    }
}

function Update-Categories {
    param(
        [string[]] $Cats,
        [int]      $Value # 1 for enable, 0 for disable
    )
    $actionVerb = if ($Value -eq 1) { "Enabling" } else { "Disabling" }
    Write-Log -Message "$actionVerb audit categories: $($Cats -join ', ')" -Level INFO

    $allCats  = Get-Categories
    $catsListRaw = ($Cats -join ',') -split '[, ]+' | ForEach-Object { $_.Trim().ToLower() }

    if ($catsListRaw -contains 'all') {
        $catsList = $allCats.Keys
        Write-Log -Message "'all' keyword used; processing all defined categories." -Level INFO
    } else {
        $catsList = $catsListRaw
    }

    $invalid = $catsList | Where-Object { -not $allCats.ContainsKey($_) }
    if ($invalid) {
        Write-Log -Message "Unknown category(s) specified: $($invalid -join ', '). Aborting update for these." -Level ERROR
        # Decide if we should return or continue with valid ones. For now, returning.
        return
    }

    foreach ($cat in $catsList) {
        Write-Log -Message "Processing category: $cat" -Level DEBUG
        foreach ($id in $allCats[$cat].IDs) {
            $map  = Get-AuditMapping -EventId $id
            if (-not $map) {
                Write-Log -Message "No audit mapping found for Event ID $id in category $cat during update." -Level WARN
                continue
            }
            if (-not $AdvSubCatGuidMap.ContainsKey($map.RegistryPath)) {
                Write-Log -Message "GUID not found in AdvSubCatGuidMap for RegistryPath '$($map.RegistryPath)' (Event ID $id) during update." -Level WARN
                continue
            }
            $guid = $AdvSubCatGuidMap[$map.RegistryPath]
            $mode = if ($Value -eq 1) { 'enable' } else { 'disable' }
            $auditPolAction = if ($Value -eq 1) { "/success:enable /failure:enable" } else { "/success:disable /failure:disable" }

            $shouldProcessMessage = "Set audit policy for $($map.SubCategory) (EventID $id, GUID $guid) to $mode"
            # Construct the command arguments for the call operator &
            $auditpolArgs = @("/set", "/subcategory:""$guid""", "/success:$mode", "/failure:$mode")
            $commandStringForLog = "auditpol.exe $($auditpolArgs -join ' ')" # For logging and ShouldProcess message

            if ($PSCmdlet.ShouldProcess($commandStringForLog, $shouldProcessMessage)) {
                Write-Log -Message "Executing: $commandStringForLog" -Level INFO
                Write-Log -Message "Debug: Arguments passed to auditpol: $auditpolArgs" -Level DEBUG

                # Using the call operator & with an array of arguments
                & auditpol.exe $auditpolArgs

                if ($LASTEXITCODE -ne 0) {
                    Write-Log -Message "auditpol.exe failed to set subcategory $($map.SubCategory) (ID $id, GUID $guid). Exit code: $LASTEXITCODE. Command: $commandStringForLog" -Level ERROR
                } else {
                    Write-Log -Message "Successfully $mode-d auditing for $($map.SubCategory) (ID $id, GUID $guid)" -Level INFO
                    Write-Host "$mode $($map.SubCategory) ($id)" -ForegroundColor $allCats[$cat].Color # Keep console confirmation
                }
            } else {
                Write-Log -Message "Skipped (ShouldProcess): $shouldProcessMessage" -Level INFO
            }
        }
    }
    Write-Log -Message "Finished $actionVerb categories: $($catsList -join ', ')" -Level INFO
    Write-Host "`n$actionVerb categories: $($catsList -join ', ')" -ForegroundColor Cyan # Keep console summary
}

function Get-AuditMapping {
    param([int]$EventId)
    $mappings = @(
        @{Id=4624; RegistryPath='AuditLogon';                           SubCategory='Logon'},
        @{Id=4625; RegistryPath='AuditLogoff';                          SubCategory='Logoff'},
        @{Id=4768; RegistryPath='AuditKerberosAuthentication';          SubCategory='Kerberos-TGT Request'},
        @{Id=4769; RegistryPath='AuditKerberosServiceTicketOperations'; SubCategory='Kerberos-Service Ticket'},
        @{Id=4771; RegistryPath='AuditKerberosPreAuth';                 SubCategory='Kerberos Pre-auth'},
        @{Id=4772; RegistryPath='AuditKerberosAuthentication';          SubCategory='Kerberos-TGS Request'},
        @{Id=4776; RegistryPath='AuditNTLMAuthentication';              SubCategory='NTLM Authentication'},
        @{Id=4777; RegistryPath='AuditNTLMAuthentication';              SubCategory='NTLM Auth Failure'},
        @{Id=4720; RegistryPath='AuditUserAccountManagement';            SubCategory='User Account Created'},
        @{Id=4722; RegistryPath='AuditUserAccountManagement';            SubCategory='User Account Enabled'},
        @{Id=4724; RegistryPath='AuditUserAccountManagement';            SubCategory='Password Reset'},
        @{Id=4725; RegistryPath='AuditUserAccountManagement';            SubCategory='User Account Disabled'},
        @{Id=4726; RegistryPath='AuditUserAccountManagement';            SubCategory='User Account Deleted'},
        @{Id=4727; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Group Created'},
        @{Id=4728; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Member Added to Global Group'},
        @{Id=4729; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Member Removed from Global Group'},
        @{Id=4730; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Global Group Deleted'},
        @{Id=4731; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Local Group Created'},
        @{Id=4732; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Member Added to Local Group'},
        @{Id=4733; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Member Removed from Local Group'},
        @{Id=4734; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Local Group Deleted'},
        @{Id=4735; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Local Group Changed'},
        @{Id=4737; RegistryPath='AuditSecurityGroupManagement';          SubCategory='Global Group Changed'},
        @{Id=4754; RegistryPath='AuditDistributionGroupManagement';      SubCategory='Universal Group Created'},
        @{Id=4755; RegistryPath='AuditDistributionGroupManagement';      SubCategory='Universal Group Changed'},
        @{Id=4756; RegistryPath='AuditDistributionGroupManagement';      SubCategory='Member Added to Universal Group'},
        @{Id=4757; RegistryPath='AuditDistributionGroupManagement';      SubCategory='Member Removed from Universal Group'},
        @{Id=4758; RegistryPath='AuditDistributionGroupManagement';      SubCategory='Universal Group Deleted'},
        @{Id=5136; RegistryPath='AuditDirectoryServiceChanges';         SubCategory='Directory Service Modify'},
        @{Id=5137; RegistryPath='AuditDirectoryServiceChanges';         SubCategory='Directory Service Create'},
        @{Id=5138; RegistryPath='AuditDirectoryServiceChanges';         SubCategory='Directory Service Delete'},
        @{Id=4662; RegistryPath='AuditDirectoryServiceAccess';          SubCategory='Directory Service Access'},
        @{Id=4663; RegistryPath='AuditDirectoryServiceChanges';         SubCategory='Directory Service Changes'},
        @{Id=6400; RegistryPath='AuditKDCPolicyChange';                 SubCategory='KDC Policy Change'},
        @{Id=6401; RegistryPath='AuditKDCPolicyChange';                 SubCategory='KDC Service Start'},
        @{Id=4719; RegistryPath='AuditPolicyChange';                    SubCategory='Audit Policy Change'}
    )
    return $mappings | Where-Object { $_.Id -eq $EventId }
}

# Main logic

# Initial LogFilePath check before Write-Log is heavily used.
# This is a bit tricky as Write-Log itself uses LogFilePath.
# If this initial check fails, logging might go to console only if Write-Log handles it.
if ($PSBoundParameters.ContainsKey('LogFilePath')) {
    $initialLogDir = Split-Path -Path $LogFilePath -Parent
    if ($initialLogDir -and (-not (Test-Path -Path $initialLogDir -PathType Container))) {
        Write-Error "Initial check: Parent directory '$initialLogDir' for specified LogFilePath '$LogFilePath' does not exist. Script will likely fail to log to file."
        # Allow script to continue, Write-Log will attempt and fail, writing errors to console.
    }
}


Write-Log -Message "DC-LogMaster Audit Policy Script - Version $ScriptVersion - Started." -Level INFO
Write-Log -Message "Log file: $LogFilePath" -Level INFO # This will be the first attempt to write to the log file.
Write-Log -Message "Command line arguments: $($MyInvocation.Line)" -Level INFO

# Parameter Validation for file paths (moved before GPO detection for ExportPolicy)
if ($PSBoundParameters.ContainsKey('ExportPolicy')) {
    # If -ExportPolicy is explicitly used, validate its path (which could be the default or user-provided)
    if (-not (Test-ParentDirectoryWriteable -FilePath $ExportPolicy)) {
        Write-Log -Message "Validation failed for -ExportPolicy path '$ExportPolicy'. Parent directory may not exist or is not writeable. Aborting." -Level ERROR
        exit 1
    }
}
# Note: $LogFilePath is validated by Write-Log itself on first write attempt.
# $ImportPolicy is validated within its function.

# GPO Detection
$detectedGPOs = $null
# Determine if GPO detection is needed based on the *actual primary operation* intended by the user.
# GPO detection is needed for ShowCurrent, Enable, Disable, and Import. Not for Help, ShowAvailable, or Export.
$needsGPODetection = $PSBoundParameters.ContainsKey('ShowCurrent') -or
                     $PSBoundParameters.ContainsKey('Enable') -or
                     $PSBoundParameters.ContainsKey('Disable') -or
                     $PSBoundParameters.ContainsKey('ImportPolicy')

if ($needsGPODetection) {
    Write-Log -Message "Initiating GPO detection as current operation may interact with or be affected by GPOs." -Level INFO
    $detectedGPOs = Get-AdvancedAuditPolicyGPOs
    if ($detectedGPOs) {
        Write-Log -Message "GPO Detection Result: Found GPOs potentially configuring Advanced Audit Policy: $($detectedGPOs -join ', ')" -Level WARN
    } else {
        Write-Log -Message "GPO Detection Result: No GPOs found that seem to configure Advanced Audit Policy via known registry keys." -Level INFO
    }
}

# Main operational logic - ordered by explicit actions
if ($PSBoundParameters.ContainsKey('Help')) {
    Show-Help
    Write-Log -Message "Displayed help information." -Level INFO
}
elseif ($PSBoundParameters.ContainsKey('ShowAvailable')) {
    Show-Available
}
elseif ($PSBoundParameters.ContainsKey('ShowCurrent')) {
    Write-Log -Message "Operation: ShowCurrent" -Level INFO
    # The specific GPO warning for ShowCurrent is now handled inside Show-Current function itself for better context
    Show-Current
}
elseif ($PSBoundParameters.ContainsKey('Enable')) {
    Write-Log -Message "Operation: Enable categories '$($Enable -join ', ')'" -Level INFO
    $baseWarning = "CRITICAL ADVISORY: Advanced Audit Policies are typically managed by Group Policy in a domain. "
    if ($detectedGPOs) {
        $gpoSpecificWarning = "This script detected potential GPO involvement for Advanced Audit Policy based on registry key checks: $($detectedGPOs -join ', '). "
        $warningMessage = $baseWarning + $gpoSpecificWarning + "Changes made locally with this script WILL LIKELY BE OVERRIDDEN by these GPOs and may not persist or take effect as intended. It is STRONGLY RECOMMENDED to manage audit settings via the identified GPO(s)."
    } else {
        $warningMessage = $baseWarning + "While this script's registry-based GPO check did not find specific GPOs, other GPOs (especially those using standard Advanced Audit Policy configuration via 'audit.csv') WILL STILL OVERRIDE local changes. Applying local changes with 'auditpol.exe' is very likely to be ineffective or temporary. MANAGE AUDIT SETTINGS VIA GPO."
    }
    Write-Log -Message $warningMessage -Level WARN
    Write-Warning $warningMessage
    Update-Categories -Cats $Enable -Value 1
}
elseif ($PSBoundParameters.ContainsKey('Disable')) {
    Write-Log -Message "Operation: Disable categories '$($Disable -join ', ')'" -Level INFO
    $baseWarning = "CRITICAL ADVISORY: Advanced Audit Policies are typically managed by Group Policy in a domain. "
    if ($detectedGPOs) {
        $gpoSpecificWarning = "This script detected potential GPO involvement for Advanced Audit Policy based on registry key checks: $($detectedGPOs -join ', '). "
        $warningMessage = $baseWarning + $gpoSpecificWarning + "Changes made locally with this script WILL LIKELY BE OVERRIDDEN by these GPOs and may not persist or take effect as intended. It is STRONGLY RECOMMENDED to manage audit settings via the identified GPO(s)."
    } else {
        $warningMessage = $baseWarning + "While this script's registry-based GPO check did not find specific GPOs, other GPOs (especially those using standard Advanced Audit Policy configuration via 'audit.csv') WILL STILL OVERRIDE local changes. Applying local changes with 'auditpol.exe' is very likely to be ineffective or temporary. MANAGE AUDIT SETTINGS VIA GPO."
    }
    Write-Log -Message $warningMessage -Level WARN
    Write-Warning $warningMessage
    Update-Categories -Cats $Disable -Value 0
}
elseif ($PSBoundParameters.ContainsKey('ImportPolicy')) {
    Write-Log -Message "Operation: ImportPolicy from '$ImportPolicy'" -Level INFO
    Import-DCAuditPolicy -FilePath $ImportPolicy # This function contains GPO warnings
}
elseif ($PSBoundParameters.ContainsKey('ExportPolicy')) {
    # This check is based on the parameter being explicitly provided by the user.
    # $ExportPolicy variable will always have a value (default or user-provided).
    Write-Log -Message "Operation: ExportPolicy to '$ExportPolicy'" -Level INFO
    Export-DCAuditPolicy -FilePath $ExportPolicy
}
else {
    # Default action if no specific action parameters are provided by the user
    Show-Help
    Write-Log -Message "No specific action parameters provided by user, displayed help." -Level INFO
}

Write-Log -Message "DC-LogMaster Audit Policy Script - Finished." -Level INFO
