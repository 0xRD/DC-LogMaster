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
    Write-Host "`nCategories:" -ForegroundColor Yellow
    $cats = Get-Categories
    foreach ($k in $cats.Keys) {
        Write-Host ("  {0,-8} -> {1}" -f $k, ($cats[$k].IDs -join ',')) `
            -ForegroundColor $cats[$k].Color
    }
    exit
}

function Show-Available {
    Write-Host "Available categories and Event IDs:" -ForegroundColor Cyan
    $cats = Get-Categories
    foreach ($k in $cats.Keys) {
        Write-Host ("  {0,-8} -> {1}" -f $k, ($cats[$k].IDs -join ',')) `
            -ForegroundColor $cats[$k].Color
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
                3 { 'Success and Failure' }
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

    $catsList = ($Cats -join ',') -split '[, ]+' | ForEach-Object { $_.Trim().ToLowerInvariant() }
    $all      = Get-Categories
    $invalid  = $catsList | Where-Object { -not $all.ContainsKey($_) }
    if ($invalid) {
        Write-Host "Unknown category(ies): $($invalid -join ', ')" -ForegroundColor Red
        Show-Available; return
    }

    $gpo         = 'Default Domain Controllers Policy'
    $localRegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    Import-Module GroupPolicy -ErrorAction Stop

    foreach ($cat in $catsList) {
        $color = $all[$cat].Color
        foreach ($id in $all[$cat].IDs) {
            $map    = Get-AuditMapping -EventId $id
            $action = if ($Value -eq 1) { 'Enable' } else { 'Disable' }

            if ($PSCmdlet.ShouldProcess("GPO '$gpo' + local registry", "$action Event $id ($($map.SubCategory))")) {
                # 1) on modifie la GPO pour que tous les DC héritent du réglage
                Set-GPRegistryValue `
                    -Name $gpo `
                    -Key  'HKLM\System\CurrentControlSet\Control\Lsa' `
                    -ValueName $map.RegistryPath `
                    -Type DWord -Value $Value

                # 2) on applique **immédiatement** en local pour que Show-Current le voie
                Set-ItemProperty `
                    -Path  $localRegKey `
                    -Name  $map.RegistryPath `
                    -Type  DWord `
                    -Value $Value

                Write-Host "$action d Event $id ($($map.SubCategory))" -ForegroundColor $color
            }
        }
    }

    Write-Host "`nApplied categories: $($catsList -join ', ') on GPO + local registry" -ForegroundColor Cyan
    Invoke-GPUpdate -Force | Out-Null
}


function Get-AuditMapping {
    param([int]$EventId)
    $mapList = @(
        @{Id=4624; SubCategory='Logon';                    RegistryPath='AuditLogon'},
        @{Id=4625; SubCategory='Logoff';                   RegistryPath='AuditLogoff'},
        @{Id=4768; SubCategory='Kerberos-TGT Request';     RegistryPath='AuditKDCService'},
        @{Id=4769; SubCategory='Kerberos-Service Ticket';  RegistryPath='AuditKerberosService'},
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
        @{Id=4756; SubCategory='Universal Group Add';      RegistryPath='AuditSecurityGroupManagement'},
        @{Id=4757; SubCategory='Member Removed from Group';RegistryPath='AuditSecurityGroupManagement'},
        @{Id=5136; SubCategory='Directory Service Modify'; RegistryPath='AuditDirectoryServiceAccess'},
        @{Id=5137; SubCategory='Directory Service Create'; RegistryPath='AuditDirectoryServiceAccess'},
        @{Id=5138; SubCategory='Directory Service Delete'; RegistryPath='AuditDirectoryServiceAccess'},
        @{Id=6400; SubCategory='KDC Policy Change';        RegistryPath='AuditKDCPolicyChange'},
        @{Id=6401; SubCategory='KDC Service Start';        RegistryPath='AuditKDCService'}
    )
    return ($mapList | Where-Object { $_.Id -eq $EventId })
}

# Main
if      ($Help)       { Show-Help }
elseif  ($ShowAvailable) { Show-Available }
elseif  ($ShowCurrent)   { Show-Current }
elseif  ($Enable)        { Update-Categories -Cats $Enable  -Value 1 }
elseif  ($Disable)       { Update-Categories -Cats $Disable -Value 0 }
else                  { Show-Help }
