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
    [string[]]             $Disable
)

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
        low           = @{ IDs = @(4624,4625);                                    Color = 'Green'   }
        medium        = @{ IDs = @(4768,4769,4771,4776);                          Color = 'Yellow'  }
        high          = @{ IDs = @(5136,5137,5138,6400,6401,4662,4663);           Color = 'Red'     }
        accounts      = @{ IDs = @(4720,4722,4724,4725,4726);                     Color = 'Magenta' }
        groups        = @{ IDs = @(4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758); Color = 'Cyan'    }
        kerberos      = @{ IDs = @(4768,4769,4771,4772,4776,4777);                 Color = 'Yellow'  }
        objectaccess  = @{ IDs = @(4662,4663);                                    Color = 'Blue'    }
        policychange  = @{ IDs = @(4719);                                          Color = 'Magenta' }
    }
}

function Show-Help {
    Write-Host 'Usage: .\Set-DCLogging.ps1 [options]' -ForegroundColor Cyan
    Write-Host '  -h, --help         Show this help message'
    Write-Host '  -ShowCurrent       Display current auditpol settings'
    Write-Host '  -ShowAvailable     List categories and their Event IDs'
    Write-Host '  -Enable <cats>     Enable categories (use "all" for all)'
    Write-Host '  -Disable <cats>    Disable categories (use "all" for all)' -ForegroundColor DarkGray
    Write-Host 'Categories - verbosity & detection focus:' -ForegroundColor Yellow
    Write-Host '  low           -> low verbosity (essential events)' -ForegroundColor Green
    Write-Host '  medium        -> medium verbosity (additional events)' -ForegroundColor Yellow
    Write-Host '  high          -> high verbosity (detailed + object access)' -ForegroundColor Red
    Write-Host '  accounts      -> account management events' -ForegroundColor Magenta
    Write-Host '  groups        -> security group management events' -ForegroundColor Cyan
    Write-Host '  kerberos      -> Kerberos authentication events' -ForegroundColor Yellow
    Write-Host '  objectaccess  -> directory service access (4662,4663)' -ForegroundColor Blue
    Write-Host '  policychange  -> audit policy change events (4719)' -ForegroundColor Magenta
}

function Show-Available {
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
        Write-Host ("  {0,-12} {1,-20} -> {2}" -f $category, $desc, ($cats[$category].IDs -join ',')) -ForegroundColor $cats[$category].Color
    }
}

function Get-SubcategoryStatus {
    param([string]$Guid)
    $output = auditpol /get /subcategory:"$Guid" 2>&1
    if ($output -match 'Success and Failure') { return 'SuccessAndFailure' }
    elseif ($output -match '\bSuccess\b') { return 'Success' }
    elseif ($output -match '\bFailure\b') { return 'Failure' }
    else { return 'NotConfigured' }
}

function Show-Current {
    Write-Host 'Current audit settings (auditpol):' -ForegroundColor Cyan
    $cats = Get-Categories
    foreach ($category in $cats.Keys) {
        Write-Host "`n$($category):" -ForegroundColor $cats[$category].Color
        foreach ($id in $cats[$category].IDs) {
            $map = Get-AuditMapping -EventId $id
            $guid = $AdvSubCatGuidMap[$map.RegistryPath]
            $status = Get-SubcategoryStatus -Guid $guid
            Write-Host ("  {0} ({1}): {2}" -f $id, $map.SubCategory, $status)
        }
    }
}

function Update-Categories {
    param(
        [string[]] $Cats,
        [int]      $Value
    )
    $allCats  = Get-Categories
    $catsListRaw = ($Cats -join ',') -split '[, ]+' | ForEach-Object { $_.Trim().ToLower() }
    if ($catsListRaw -contains 'all') {
        $catsList = $allCats.Keys
    } else {
        $catsList = $catsListRaw
    }
    $invalid = $catsList | Where-Object { -not $allCats.ContainsKey($_) }
    if ($invalid) {
        Write-Host "Unknown category(s): $($invalid -join ', ')" -ForegroundColor Red
        return
    }
    foreach ($cat in $catsList) {
        foreach ($id in $allCats[$cat].IDs) {
            $map  = Get-AuditMapping -EventId $id
            $guid = $AdvSubCatGuidMap[$map.RegistryPath]
            $mode = if ($Value -eq 1) { 'enable' } else { 'disable' }
            if ($PSCmdlet.ShouldProcess('auditpol', "$mode $($map.SubCategory) ($id)")) {
                auditpol /set /subcategory:"$guid" /success:$mode /failure:$mode | Out-Null
                Write-Host "$mode $($map.SubCategory) ($id)" -ForegroundColor $allCats[$cat].Color
            }
        }
    }
    Write-Host "`nApplied categories: $($catsList -join ', ')" -ForegroundColor Cyan
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
if ($Help) {
    Show-Help
} elseif ($ShowAvailable) {
    Show-Available
} elseif ($ShowCurrent) {
    Show-Current
} elseif ($Enable) {
    Update-Categories -Cats $Enable -Value 1
} elseif ($Disable) {
    Update-Categories -Cats $Disable -Value 0
} else {
    Show-Help
}
