
function Search-WhoUser {

    param (
        [string] $searchText = $(throw "-searchText is required")
    )

    #----------------------------------------
    # Get-ADUser Properties
    #----------------------------------------

    #Specifies the properties that are used in Get-ADUser -Properties
    $UserProperties = "SamAccountName", "Name","CanonicalName","idmADDomain","HomeDirectory","EQCentreCode","EmployeeNumber","mail","msExchHomeServerName","EQIdentityType","ProfilePath","Title","Enabled","info","AccountExpirationDate","Created","Modified","PasswordLastSet","LastLogonDate","Department","Office","PasswordExpired","LockedOut","LastBadPasswordAttempt","StreetAddress","msDS-UserPasswordExpiryTimeComputed","MemberOf"
    $ResUserProperties = "SamAccountName", "Name","CanonicalName","HomeDirectory","EmployeeNumber","mail","ProfilePath","Title","Enabled","info","AccountExpirationDate","Created","Modified","PasswordLastSet","LastLogonDate","Department","Office","PasswordExpired","LockedOut","LastBadPasswordAttempt","StreetAddress","msDS-UserPasswordExpiryTimeComputed","MemberOf"

    #Specifies the properties that are selected in the Select-Object Commandlet
    $UserSelectProperties =
    @{n="Username"; e={$_.SamAccountName}},
    "Name",
    @{n="OU"; e={$_.CanonicalName}},
    @{n="Domain"; e={$Domain}},
    @{n="Home Directory"; e={$_.HomeDirectory}},
    @{n="EQCentreCode"; e={$_.EQCentreCode}},
    @{n="Employee Number"; e={$_.EmployeeNumber}},
    @{n="Exchange Server"; e={($_.msExchHomeServerName.Replace('/','') -split ",*..=")[4]}},
    @{n="Email Address"; e={"$($_.mail)"}},
    @{n="Staff/Student"; e={$_.EQIdentityType}},
    @{n="Profile Path"; e={"$(if($_.ProfilePath -and $_.EQIdentityType -eq "Staff") {$_.ProfilePath + " <-- Staff with Profile Path"} Else {$_.ProfilePath})"}},
    @{n="Account Status"; e={"$(if ($_.Enabled -eq $true) {"Account is enabled"} Else {"Account is disabled"})"}},
    @{n="Account Expiry Status"; e={"$(if ($_.AccountExpirationDate -eq $null) {"No Expiry Date Set"} Elseif ($_.AccountExpirationDate -lt (Get-Date)) {"Account has expired"} else {"Account has not expired"})"}},
    @{n="IDM Status"; e={"$(if(!$_.info) {"IDM status not set - Indicates privileged account"} Else {$_.info})"}},
    @{n="Password Status"; e={"$(if ($_.PasswordExpired -eq $False) {"Password has not expired"} Else {"Password has expired"})"}},
    @{n="Lockout Status"; e={"$(if ($_.LockedOut -eq $False) {"Account is not locked out"} Else {"Account is locked out"})"}},
    @{n="Account Expiry Date"; e={$_.AccountExpirationDate.Tostring("HH:mm dd/MM/yyyy")}},
    @{n="Account Created"; e={$_.Created.Tostring("HH:mm dd/MM/yyyy")}},
    @{n="Account Last Modified"; e={$_.Modified.Tostring("HH:mm dd/MM/yyyy")}},
    @{n="Password Expiry Date"; e={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed").Tostring("HH:mm dd/MM/yyyy")}},
    @{n="Password Last Set"; e={$_.PasswordLastSet.Tostring("HH:mm dd/MM/yyyy")}},
    @{n="Last Bad Password Attempt"; e={$_.LastBadPasswordAttempt.Tostring("HH:mm dd/MM/yyyy")}},
    @{n="Last Logon Date"; e={$_.LastLogonDate.Tostring("HH:mm dd/MM/yyyy")}},
    @{n="Occupation"; e={$_.Title}},
    @{n="Street Address"; e={$_.StreetAddress}},
    "Department",
    @{n="Office"; e={"$($_.Office)"}},
    @{n="Groups + DLs"; e={$Data = foreach ($line in $_.MemberOf) {($line -split ",")[0] -replace "CN="}; ($Data | Sort-Object) -join "`r`n"}}

    #----------------------------------------
    # Get-AD Query
    #----------------------------------------

    $UserQuery = 
        ForEach ($Domain in $Domains) { #Does the below command for each of the domains in the array (Allows it to search for a user in all regions) and saves it as a variable
            if ($Domain -like "RES*") {
                Get-ADUser -Server $Domain -Properties $ResUserProperties -Filter {(SamAccountName -like $searchText) -or (EmailAddress -like $searchText) -or (EmployeeNumber -like $searchText) -or (Name -like $searchText)} -ErrorAction SilentlyContinue | Select-Object $UserSelectProperties
                #Get-ADUser command queries the domains using the properties specified - it -filters the input and searches for any matches in username, email, or employee number - it | the results into the Select-Object, allowing us to grab what we actually want - it | this to Format-List which does what it says - it | this to the powershell host displaying it for the consultant
            } else {
                Get-ADUser -Server $Domain -Properties $UserProperties -Filter {(SamAccountName -like $searchText) -or (EmailAddress -like $searchText) -or (EmployeeNumber -like $searchText) -or (Name -like $searchText)} -ErrorAction SilentlyContinue | Select-Object $UserSelectProperties
            }
        }

    $EndResult =
    foreach ($Result in $UserQuery) {
        if (!($Result)) {
            $UserQuery = $UserQuery | Where-Object {$UserQuery -notcontains $Result}
        } else {
            $Result
        }
    }

    return $EndResult
   
}

function Search-WhoComputer {

    param (
        [string] $searchText = $(throw "-searchText is required")
    )

    #-----------------------------------------
    # Get-ADComputer Properties
    #-----------------------------------------
    $ComputerProperties = "DNSHostName","IPv4Address","CanonicalName","OperatingSystem","OperatingSystemVersion","Description","Created","Modified","LastLogonDate","logonCount","MemberOf"

    $ComputerSelectProperties = 
    @{n="HostName"; e={$_.DNSHostName}},
    @{n="IP Address"; e={"$(if(!$_.IPv4Address) {"Checked DNS PTR Records - No IP Reported"} Else {$_.IPv4Address})"}},
    @{n="OU"; e={$_.CanonicalName}},
    @{n="Operating System"; e={$_.OperatingSystem}},
    @{n="OS Version"; e={$_.OperatingSystemVersion}},
    "Description",
    @{n="Device Created"; e={$_.Created}},
    @{n="Device Modified"; e={$_.Modified}},
    @{n="Last Logged On"; e={$_.LastLogonDate}},
    @{n="Groups"; e={$Data = foreach ($line in $_.MemberOf) {($line -split ",")[0] -replace "CN="}; ($Data | Sort-Object) -join "`r`n"}}
    #-----------------------------------------
    # Get-ADComputer Main Loop
    #-----------------------------------------
    $ComputerQuery = 
        foreach ($Domain in $Domains) {
            try {
                Get-ADComputer -Server $Domain  -Properties $ComputerProperties -Filter {(name -eq $searchText) -or (name -like $searchText)} -ErrorAction SilentlyContinue | Select-Object $ComputerSelectProperties
            } Catch {}
        }

    $EndResult =
        foreach ($Result in $ComputerQuery) {
            if (!($Result)) {
                $ComputerQuery = $ComputerQuery | Where-Object {$ComputerQuery -notcontains $Result}
            } else {
                $Result
            }
        }

    return $EndResult

}

function Search-WhoGroup {

    param (
        [string] $searchText = $(throw "-searchText is required")
    )
    
    #-----------------------------------------
    # Get-ADGroup Properties
    #-----------------------------------------
    $GroupProperties = "Name","CanonicalName","Created","Modified","Description","info","MemberOf","Members"

    $GroupSelectProperties = 
    @{n="Group Name"; e={$_.Name}},
    "CanonicalName",
    "Created",
    "Modified",
    "Description",
    @{n="Server/Share Information"; e={"$($_.info)`r`n"}},
    @{n="Groups + DLs"; e={"$($Data = foreach ($line in $_.MemberOf) {($line -split ",")[0] -replace "CN="}; ($Data | Sort-Object) -join "`r`n")`r`n"}},
    @{n="Members"; e={$Data = foreach ($line in $_.Members) {if (($line -like "*Policy*") -or ($line -like "*Deleted*")) {($line -split "OU=")[0] -replace "," -replace "\\" -replace "CN="} else {($line -split ",")[0] -replace "CN="}}; ($Data | Sort-Object) -join "`r`n"}}
    #-----------------------------------------
    # Get-ADGroup Main Loop
    #-----------------------------------------
    $GroupQuery = 
        foreach ($Domain in $Domains) {
            try {
                Get-ADGroup -filter {(Name -eq $searchText) -or (Name -like $searchText)} -Properties $GroupProperties -Server $Domain | Select-Object $GroupSelectProperties
            } catch{}
        }

    $EndResult =
        foreach ($Result in $GroupQuery) {
            if (!($Result)) {
                $GroupQuery = $GroupQuery | Where-Object {$GroupQuery -notcontains $Result}
            } else {
                $Result
            }
        }

    return $EndResult

}    