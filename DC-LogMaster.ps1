<#
.SYNOPSIS
    DC-LogMaster: Manage and strengthen Domain Controller audit settings
.DESCRIPTION
    Configures advanced audit policy on a Domain Controller using auditpol with GUIDs,
    eliminating language/localization issues. Registry writes have been removed; only
    advanced audit policy via auditpol is used.
.TO DO
    Ensure the GUIDs in $advSubCatGuidMap match your environment.
    To list subcategory GUIDs, run:
        auditpol /list /subcategory:* /format:csv
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [alias('h','?')][switch]   $Help,
    [switch]                  $ShowCurrent,
    [switch]                  $ShowAvailable,
    [string[]]                $Enable,
    [string[]]                $Disable
)

function Get-Categories {
    @{   
        low      = @{ IDs = @(4624,4625);                   Color = 'Green'   }
        medium   = @{ IDs = @(4768,4769,4771,4776);         Color = 'Yellow'  }
        high     = @{ IDs = @(5136,5137,5138,6400,6401);    Color = 'Red'     }
        accounts = @{ IDs = @(4720,4722,4724,4725,4726);     Color = 'Magenta' }
        groups   = @{ IDs = @(4727,4728,4732,4756,4757);     Color = 'Cyan'    }
        kerberos = @{ IDs = @(4768,4769,4771,4772,4776,4777);Color = 'Yellow'  }
    }
}

function Show-Help {
    Write-Host "Usage: .\Set-DCLogging.ps1 [options]" -ForegroundColor Cyan
    Write-Host "  -h, --help         Show this help message"
    Write-Host "  -ShowCurrent       Display current audit settings (registry)"
    Write-Host "  -ShowAvailable     List categories and their Event IDs"
    Write-Host "  -Enable <cats>     Enable one or more categories"
    Write-Host "  -Disable <cats>    Disable one or more categories"
    Write-Host "  -WhatIf            Simulate changes" -ForegroundColor DarkGray
    Write-Host "`nCategories - verbosity levels:" -ForegroundColor Yellow
    Write-Host "  low      -> low verbosity (essential events)" -ForegroundColor Green
    Write-Host "  medium   -> medium verbosity (additional events)" -ForegroundColor Yellow
    Write-Host "  high     -> high verbosity (more detailed events)" -ForegroundColor Red
    Write-Host "  accounts -> account management audit" -ForegroundColor Magenta
    Write-Host "  groups   -> group management audit" -ForegroundColor Cyan
    Write-Host "  kerberos -> Kerberos audit" -ForegroundColor Yellow
    exit
}

function Show-Available {
    Write-Host "Available categories and Event IDs - verbosity levels:" -ForegroundColor Cyan
    $cats = Get-Categories
    foreach ($k in $cats.Keys) {
        $desc = switch ($k) {
            'low'      {'(low verbosity)'}
            'medium'   {'(medium verbosity)'}
            'high'     {'(high verbosity)'}
            'accounts' {'(account management)'}
            'groups'   {'(group management)'}
            'kerberos' {'(Kerberos audit)'}
            default    {''}
        }
        Write-Host ("  {0,-8} {1,-18} -> {2}" -f $k, $desc, ($cats[$k].IDs -join ',')) -ForegroundColor $cats[$k].Color
    }
}

function Show-Current {
    Write-Host "Current audit settings (registry):" -ForegroundColor Cyan

    $regPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    $cats    = Get-Categories

    foreach ($key in $cats.Keys) {
        $info = $cats[$key]
        Write-Host "`n$($key):" -ForegroundColor $info.Color

        foreach ($id in $info.IDs) {
            $map  = Get-AuditMapping -EventId $id
            $prop = $map.RegistryPath
            $val  = (Get-ItemProperty -Path $regPath -Name $prop -ErrorAction SilentlyContinue).$prop
            if ($null -eq $val) { $val = 0 }
            $state = switch ($val) {
                0 { 'Disabled' }
                1 { 'Success' }
                2 { 'Failure' }
                3 { 'SuccessAndFailure' }
                default { 'Unknown' }
            }
            Write-Host ("  {0} ({1}): {2}" -f $id, $map.SubCategory, $state)
        }
    }
}

function Update-Categories {
    param(
        [string[]] $Cats,
        [int]      $Value
    )

    # Map RegistryPath to subcategory GUID (language independent)
    $advSubCatGuidMap = @{  
        'AuditLogon'                          = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        'AuditLogoff'                         = '{0CCE9216-69AE-11D9-BED3-505054503030}'
        'AuditKerberosAuthentication'         = '{0CCE9242-69AE-11D9-BED3-505054503030}'
        'AuditKerberosServiceTicketOperations'= '{0CCE9240-69AE-11D9-BED3-505054503030}'
        'AuditKerberosPreAuth'                = '{0CCE923F-69AE-11D9-BED3-505054503030}'
        'AuditNTLMAuthentication'             = '{0CCE9227-69AE-11D9-BED3-505054503030}'
        'AuditUserAccountManagement'          = '{0CCE9235-69AE-11D9-BED3-505054503030}'
        'AuditSecurityGroupManagement'        = '{0CCE9237-69AE-11D9-BED3-505054503030}'
        'AuditDistributionGroupManagement'    = '{0CCE9238-69AE-11D9-BED3-505054503030}'
        'AuditApplicationGroupManagement'     = '{0CCE9239-69AE-11D9-BED3-505054503030}'
        'AuditDirectoryServiceAccess'         = '{0CCE923C-69AE-11D9-BED3-505054503030}'
        'AuditKDCPolicyChange'                = '{0CCE9230-69AE-11D9-BED3-505054503030}'
        'AuditKDCService'                     = '{0CCE9230-69AE-11D9-BED3-505054503030}'
    }

    # Validate categories
    $catsList = ($Cats -join ',') -split '[, ]+' | % { $_.Trim().ToLowerInvariant() }
    $all      = Get-Categories
    $invalid  = $catsList | Where-Object { -not $all.ContainsKey($_) }
    if ($invalid) {
        Write-Host "Unknown category(s): $($invalid -join ', ')" -ForegroundColor Red
        Show-Available; return
    }

    Import-Module GroupPolicy -ErrorAction Stop

    foreach ($cat in $catsList) {
        $color = $all[$cat].Color
        foreach ($id in $all[$cat].IDs) {
            $map  = Get-AuditMapping -EventId $id
            $mode = if ($Value -eq 1) { 'enable' } else { 'disable' }

            if ($PSCmdlet.ShouldProcess("auditpol", "$mode Event $id ($($map.SubCategory))")) {
                Write-Host "$mode Event $id ($($map.SubCategory))" -ForegroundColor $color

                # Apply advanced audit policy via GUID
                $guid = $advSubCatGuidMap[$map.RegistryPath]
                if ($guid) {
                    & auditpol /set /subcategory:$guid /success:$mode /failure:$mode | Out-Null
                    Write-Host "Applied auditpol on GUID $guid ($($map.SubCategory)) : $mode" -ForegroundColor $color
                } else {
                    & auditpol /set /subcategory:"$($map.SubCategory)" /success:$mode /failure:$mode | Out-Null
                    Write-Host "Applied auditpol on subcategory '$($map.SubCategory)' : $mode" -ForegroundColor $color
                }
            }
        }
    }

    Write-Host "`nApplied categories: $($catsList -join ', ') via auditpol" -ForegroundColor Cyan

    # Force GPO update
    Invoke-GPUpdate -Force | Out-Null
}

function Get-AuditMapping {
    param([int]$EventId)
    $mapList = @(    
        @{Id=4624; SubCategory='Logon';                    RegistryPath='AuditLogon'},
        @{Id=4625; SubCategory='Logoff';                   RegistryPath='AuditLogoff'},
        @{Id=4768; SubCategory='Kerberos-TGT Request';     RegistryPath='AuditKDCService'},
        @{Id=4769; SubCategory='Kerberos-Service Ticket';  RegistryPath='AuditKerberosServiceTicketOperations'},
        @{Id=4771; SubCategory='Kerberos Pre-auth';        RegistryPath='AuditKerberosPreAuth'},
        @{Id=4772; SubCategory='Kerberos-TGS Request';     RegistryPath='AuditKDCService'},
        @{Id=4776; SubCategory='NTLM Authentication';      RegistryPath='AuditNTLMAuthentication'},
        @{Id=4777; SubCategory='NTLM Auth Failure';        RegistryPath='AuditNTLMAuthentication'},
        @{Id=4720; SubCategory='User Account Created';     RegistryPath='AuditUserAccountManagement'},
        @{Id=4722; SubCategory='User Account Enabled';     RegistryPath='AuditUserAccountManagement'},
        @{Id=4724; SubCategory='Password Reset';           RegistryPath='AuditUserAccountManagement'},
        @{Id=4725; SubCategory='User Account Disabled';    RegistryPath='AuditUserAccountManagement'},
        @{Id=4726; SubCategory='User Account Deleted';     RegistryPath='AuditUserAccountManagement'},
        @{Id=4727; SubCategory='Group Created';            RegistryPath='AuditSecurityGroupManagement'},
        @{Id=4728; SubCategory='Member Added to Group';    RegistryPath='AuditSecurityGroupManagement'},
        @{Id=4732; SubCategory='Local Group Add Member';   RegistryPath='AuditSecurityGroupManagement'},
        @{Id=4756; SubCategory='Universal Group Add';      RegistryPath='AuditDistributionGroupManagement'},
        @{Id=4757; SubCategory='Member Removed from Group';RegistryPath='AuditDistributionGroupManagement'},
        @{Id=5136; SubCategory='Directory Service Modify'; RegistryPath='AuditDirectoryServiceAccess'},
        @{Id=5137; SubCategory='Directory Service Create'; RegistryPath='AuditDirectoryServiceAccess'},
        @{Id=5138; SubCategory='Directory Service Delete'; RegistryPath='AuditDirectoryServiceAccess'},
        @{Id=6400; SubCategory='KDC Policy Change';        RegistryPath='AuditKDCPolicyChange'},
        @{Id=6401; SubCategory='KDC Service Start';        RegistryPath='AuditKDCService'}
    )
    return ($mapList | Where-Object { $_.Id -eq $EventId })
}

# Main
if      ($Help)          { Show-Help }
elseif  ($ShowAvailable) { Show-Available }
elseif  ($ShowCurrent)   { Show-Current }
elseif  ($Enable)        { Update-Categories -Cats $Enable  -Value 1 }
elseif  ($Disable)       { Update-Categories -Cats $Disable -Value 0 }
else                    { Show-Help }
