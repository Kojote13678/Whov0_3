Add-Type -AssemblyName System.Windows.Forms

Import-Module ActiveDirectory

function Get-PrivilegedAccounts {
    param (
        [Parameter(Mandatory = $true)][string]$Server
    )
    $User = $Env:USERNAME
    $CORPSearchBase = "OU=8834_Admin Accounts,OU=8834_Privileged Accounts,DC=corp,DC=qed,DC=qld,DC=gov,DC=au"
    $GBNSearchBase = "OU=5584_Admin Accounts,OU=5584_Privileged Accounts,DC=gbn,DC=eq,DC=edu,DC=au"

    if ($Server -like "CORP") {
        return Get-ADUser -LDAPFilter "(SamAccountName=*-$Env:USERNAME)" -server $Server -SearchBase $CORPSearchBase -Properties AccountExpirationDate, Enabled, PasswordExpired, SamAccountName | Where-Object { (($_.Enabled -eq $true) -and ($_.AccountExpirationDate -gt (Get-Date)) -and ($_.PasswordExpired -eq $false)) }
    } else {
        return Get-ADUser -LDAPFilter "(SamAccountName=*-$User)" -Server "gbn.eq.edu.au" -SearchBase $GBNSearchBase -Properties AccountExpirationDate, Enabled, PasswordExpired, SamAccountName | Where-Object {(($_.Enabled -eq $true) -and ($_.AccountExpirationDate -gt (Get-Date)) -and ($_.PasswordExpired -eq $false))}
    }
    
    
}

function Get-HighestAccount {
    param (
        [Parameter(Mandatory = $true)][string]$Server
    )

    $PrefixPriority = @{
        "ZZ" = 5
        "SS" = 4
        "ST" = 3
        "SC" = 2
        "OC" = 1
    }
    
    $Value = 0
    $HighestAccount = "NA"
    $PrivAccounts = Get-PrivilegedAccounts -Server $Server
    
    foreach ($Account in $PrivAccounts) {
        $Username = $Account.SamAccountName

        if (!$Username.Contains('-')) { Continue }
    
        $Prefix = $Username.Split('-')[0].ToUpper()
        
        If (!($PrefixPriority.ContainsKey($Prefix))) { Continue }

        If ($Value -lt $PrefixPriority.$Prefix) {
            $Value = $PrefixPriority.$Prefix
            $HighestAccount = $Username
        }
        
    }
    
    Return "$($Server.Split('.')[0])\$HighestAccount"
}

function Get-PrivilegedCredential {
    param (
        [string]$Domain
    )

    if ($Domain -eq $global:svrCORP) {
        $PrivAccount = $global:CORPPrivAccount
    }
    else {
        $PrivAccount = $global:SchoolPrivAccount
    }

    return Get-Credential -UserName $PrivAccount -Message "Please enter your privileged account credentials"
}

function Open-ActiveDirectory {
    param (
        [Parameter(Mandatory = $true)][string]$Server
    )

    if ($Server -match $global:svrCORP) {
        $Username = $global:CORPPrivAccount
    }
    else {
        $Username = $global:SchoolPrivAccount
    }

    try {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/C runas /netonly /user:$Username ""mmc.exe dsa.msc /DOMAIN=$Server"""
        Write-Log -ID 1 -Message "Successfully opened Active Directory Users and Computers (dsa.msc)" -Server $Server -Credential $Username

    }
    Catch {
        Show-MessageBox -Message $_ -Title "Error"
        Write-Log -ID 1 -Error -Message "Failed to open Active Directory Users and Computers (dsa.msc)" -Server $Server -Credential $Username

    }
    
}

function Show-MessageBox {
    param (
        [string]$Message,
        [string]$Title = "Attention"
    )

    [System.Windows.Forms.MessageBox]::Show($Message, $Title)
}
