Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Import-Module ActiveDirectory

Class WhoComputer {
    $Computer

    WhoComputer($Computer) {
        $this.Computer = $Computer
    }

    [void] AppendToRTB(
        [System.Windows.Forms.RichTextBox]$RTB
    ) {
        Append-ObjectToRTB -RTB $RTB
    }

    [void] CopyToClipboard() {
        Set-Clipboard $this.ToString()
    }

    [string] ToString() {
        $Text = ""
        $this.Computer.PSObject.Properties | ForEach-Object {
            $Text += $_.Name + ': ' + $_.Value + [System.Environment]::NewLine
        }
        Return $Text
    }

    [string] GetDomainController() {
        $CentreCode = ($This.Computer.HostName -replace '[a-z]').Substring(0, 4)
        return @(Get-ADDomainController -Filter { Name -like "*$CentreCode*" } -Server ((($This.Computer.OU) -split "/")[0]) | Select-Object -ExpandProperty HostName)[0]
    }

    [void] EditADCore() {
        $Core = (($this.Computer.OU) -split "/")[0] 
        Open-ActiveDirectory -Server $Core
    }

    [void] EditADEdge() {
        $CentreCode = ($this.Computer.HostName -replace '[a-z]').Substring(0, 4)
        $Core = (($this.Computer.OU) -split "/")[0]
        $Edge = @(Get-ADDomainController -Filter { Name -like "*$CentreCode*" } -Server $Core | Select-Object -ExpandProperty HostName)[0]

        if ($Edge -ne $null) {
            Open-ActiveDirectory -Server $Edge
        }
        else {
            Show-MessageBox -Message "No DC can be found using $CentreCode as a centre code" -Title 'Error'
        }   
    }

    [void] Ping() {
        $Hostname = $this.Computer.HostName
        Start-Process ping "$($Hostname) /t"
    }

    [bool] IsSchoolComputer() {
        return ($this.Computer.Domain -ne $global:svrCORP)
    }

    [void] RemoteAssist() {

        if (Test-Connection -ComputerName $this.Computer.HostName -Count 2 -Quiet) {
            if ($this.IsSchoolComputer()) {
                Start-Process "cmd.exe" -ArgumentList "/C runas /netonly /user:$($Global:SchoolPrivAccount) ""cmd /C C:\Windows\system32\msra.exe /offerra \\$($this.Computer.HostName)" 
                write-Log -ID 14 -Message "$ENV:USERNAME attempted to Remote Assist $($this.Computer.HostName)" -Target $this.Computer.HostName -Credential $global:SchoolPrivAccount.UserName
            }
            else {
                Start-Process "cmd.exe" -ArgumentList "/C runas /netonly /user:$($Global:CORPPrivAccount) ""cmd /C C:\Windows\system32\msra.exe /offerra \\$($this.Computer.HostName)"
                write-Log -ID 14 -Message "$ENV:USERNAME attempted to Remote Assist $($this.Computer.HostName)" -Target $this.Computer.HostName -Credential $global:CORPPrivAccount.UserName
            }
        }
        else {
            Show-MessageBox "Failed to Connect to $($this.Computer.HostName)"
            Write-Log -ID
        }
    }

    [void] RemoteDesktop() {

        if (Test-Connection -ComputerName $this.Computer.HostName -Count 2 -Quiet) {
            Start-Process "mstsc.exe" -ArgumentList "/v:$($this.Computer.HostName)" 
        }
        else {
            Show-MessageBox "Failed to Connect to $($this.Computer.HostName)"
        }
    }

    [void] ComputerInfo() {
        $Hostname = $this.Computer.HostName
        $Core = ($this.Computer.OU -split "/")[0]
        $CentreCode = ($this.Computer.HostName -replace '[a-z]').Substring(0, 4)
        if ($this.IsSchoolComputer()) {
            $Edge = $this.GetDomainController()
        }

        $Cred = Get-PrivilegedCredential -Domain $Core

        if (!$Cred) {
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            Write-Log -Error -ID 100 -Message "No groups selected or entered, 'Add' pressed." -Target $this.Computer.HostName -Credential $Cred.UserName
            Return
        }

        $Option = New-CimSessionOption -Protocol Dcom

        if (Test-Connection -ComputerName $HostName -Count 2 -Quiet) {
            $Script:CIMSession = New-CimSession -ComputerName $Hostname -Credential $Cred
            $Script:InfoSession = New-CimSession -ComputerName $HostName -Credential $Cred -SessionOption $Option
        }
        else {
            Show-MessageBox -Message "Unable to connect to device $_" -Title 'Error'
            Return
        }
        
        if (Get-CimSession) {
            try {
                $Script:Info = Get-CimInstance -CimSession $Script:InfoSession -ClassName Win32_ComputerSystem | Select-Object Username, Manufacturer, Model
                $Script:Serial = Get-CimInstance -CimSession $Script:CIMSession -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber
                $Script:DriveSpace = Get-CimInstance -CimSession $Script:CIMSession -ClassName Win32_LogicalDisk -Filter "Deviceid='C:' or Deviceid='D:'" | Select-Object @{n = "Drive"; e = { $_.DeviceID } }, @{n = "Available Space"; e = { [math]::Round($_.freespace / 1000MB, 3) } }
                $Script:InstalledApps = Get-CimInstance -CimSession $Script:CIMSession -ClassName Win32_Product
                $Script:Locked = Invoke-Command -ComputerName $HostName -Credential $Cred -ScriptBlock { Get-Process -Name logonui -ErrorAction SilentlyContinue }
            }
            catch {
                Show-MessageBox -Message "$_" -Title 'Error'
            }
        }

        if ($Script:Locked) {
            $Script:Locked = "Computer locked"
        }
        else {
            $Script:Locked = "Computer not locked"
        }

        if ($Script:Info.Username -eq $null) {
            $Script:Info.Username = "No user logged on"
        }

        $InfoForm = New-Object System.Windows.Forms.Form
        $InfoForm.Text = "Computer Information"
        $InfoForm.Size = New-Object System.Drawing.Size(500, 700)
        $InfoForm.StartPosition = "CenterScreen"

        $Label = New-Object System.Windows.Forms.Label
        $Label.Location = New-Object System.Drawing.Size(10, 10)
        $Label.Size = New-Object System.Drawing.Size(260, 30)
        $Label.Text = "Computer Information:"
        $InfoForm.Controls.Add($Label)

        $InfoBox = New-Object System.Windows.Forms.ListView
        $InfoBox.Location = New-Object System.Drawing.Size(10, 40)
        $InfoBox.Size = New-Object System.Drawing.Size(450, 100)
        $InfoBox.FullRowSelect = $true
        $InfoBox.GridLines = $true
        $InfoBox.View = "Details"
        $InfoBox.Scrollable = $true
        $InfoForm.Controls.Add($InfoBox)

        [void] $InfoBox.Columns.Add("Username")
        [void] $InfoBox.Columns.Add("Manufacturer")
        [void] $InfoBox.Columns.Add("Model")
        [void] $InfoBox.Columns.Add("Serial Number")
        [void] $InfoBox.Columns.Add("Locked")
        [void] $InfoBox.Columns.Add("C Drive Space (GB)")
        [void] $InfoBox.Columns.Add("D Drive Space (GB)")

        $InfoBoxItem = New-Object System.Windows.Forms.ListViewItem($Script:Info.Username)
        [void] $InfoBoxItem.SubItems.Add($Script:Info.Manufacturer)
        [void] $InfoBoxItem.SubItems.Add($Script:Info.Model)
        [void] $InfoBoxItem.SubItems.Add($Script:Serial)
        [void] $InfoBoxItem.SubItems.Add($Script:Locked)
        [void] $InfoBoxItem.SubItems.Add(@($Script:DriveSpace."Available Space")[0])
        [void] $InfoBoxItem.SubItems.Add(@($Script:DriveSpace."Available Space")[1])

        [void] $InfoBox.Items.Add($InfoBoxItem)
        $InfoBox.AutoResizeColumns([System.Windows.Forms.ColumnHeaderAutoResizeStyle]::ColumnContent)

        $AppBox = New-Object System.Windows.Forms.ListView
        $AppBox.Location = New-Object System.Drawing.Size(10, 280)
        $AppBox.Size = New-Object System.Drawing.Size(450, 280)
        $Appbox.FullRowSelect = $true
        $AppBox.GridLines = $true
        $AppBox.View = "Details"
        $AppBox.Scrollable = $true
        $InfoForm.Controls.Add($AppBox)
    

        [Void] $AppBox.Columns.Add("Application")
        [Void] $AppBox.Columns.Add("Version")


        foreach ($Item in $Script:InstalledApps) {
            $AppBoxItem = New-Object System.Windows.Forms.ListViewItem($Item.Name)
            if ($Item.Version -ne $null) {
                [Void] $AppBoxItem.SubItems.Add($Item.Version)
            }
            [Void] $AppBox.Items.Add($AppBoxItem)
        }
        $AppBox.AutoResizeColumns([System.Windows.Forms.ColumnHeaderAutoResizeStyle]::ColumnContent)
    

        $InfoForm.ShowDialog()
    }

    [void] AddCompGroups() {
        $HostName = ($this.Computer.HostName -split "\.")[0] + '$'
        $Core = ($this.Computer.OU -split "/")[0]
        $CentreCode = ($this.Computer.HostName -replace '[a-z]').Substring(0, 4)
        $IsSchoolComputer = $this.IsSchoolComputer()
        if ($IsSchoolComputer) {
            $Edge = $this.GetDomainController()   
        }

        if ($this.IsSchoolComputer() -eq $False) {
            $SoftwareOU = "OU=8834_SoftwareProvisioning,DC=corp,DC=qed,DC=qld,DC=gov,DC=au"
            $Groups = Get-ADGroup -Filter * -SearchBase $SoftwareOU | Select-Object Name
        }
        else {
            $SoftwareOU = Get-ADOrganizationalUnit -Filter "Name -like '*$CentreCode*' -and Name -like '*Software*'" -Server $Core | Select-Object DistinguishedName
            $Groups = Get-ADGroup -Filter * -SearchBase $SoftwareOU.DistinguishedName -Server $Core | Select-Object Name
        }

        $Cred = Get-PrivilegedCredential -Domain $Core

        if (!$Cred) {
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            Write-Log -Error -ID 100 -Message "No groups selected or entered, 'Add' pressed." -Target $this.Computer.HostName -Credential $Cred.UserName
            Return
        }

        $GroupForm = New-Object System.Windows.Forms.Form
        $GroupForm.Text = "Add Groups"
        $GroupForm.Size = New-Object System.Drawing.Size(350, 350)
        $GroupForm.StartPosition = "CenterScreen"

        $Label = New-Object System.Windows.Forms.Label
        $Label.Location = New-Object System.Drawing.Size(10, 10)
        $Label.Size = New-Object System.Drawing.Size(260, 30)
        $Label.Text = "Addable groups below."
        $GroupForm.Controls.Add($Label)

        $ListBox = New-Object System.Windows.Forms.ListBox
        $ListBox.Location = New-Object System.Drawing.Size(10, 40)
        $ListBox.Size = New-Object System.Drawing.Size(240, 220)
        $ListBox.SelectionMode = 'MultiExtended'
        $GroupForm.Controls.Add($ListBox)

        $AddGroupsButton = New-Object System.Windows.Forms.Button
        $AddGroupsButton.Location = New-Object System.Drawing.Size(90, 260)
        $AddGroupsButton.Size = New-Object System.Drawing.Size(100, 20)
        $AddGroupsButton.Text = "Add Groups"
        $GroupForm.AcceptButton = $AddGroupsButton
        $GroupForm.Controls.Add($AddGroupsButton)

        foreach ($Result in $Groups) {
            [void] $ListBox.Items.Add($Result.Name)
        }

        $AddGroupsButton.Add_Click( {
                $Groups = $null
                $Groups = $ListBox.SelectedItems -split "`r`n"
    
                if ($Groups -eq $null) {
                    Show-MessageBox -Message "No Groups selected. $_" -Title 'Error'
                    Write-Log -Error -ID 109 -Message "No groups selected or entered, 'Add' pressed." -Target $this.Computer.HostName -Credential $Cred.UserName
                    return
                }
    
                if ($IsSchoolComputer) {
                    try {
                        Add-ADPrincipalGroupMembership -Identity $HostName -MemberOf $Groups -Server $Core -Credential $Cred -Confirm:$False
                        Add-ADPrincipalGroupMembership -Identity $HostName -MemberOf $Groups -Server $Edge -Credential $Cred -Confirm:$False
                        Show-MessageBox -Message "Groups added successfully on CORE and EDGE" -Title 'Success'
                        Write-Log -ID 9 -Message "Groups added successfully on CORE and EDGE.`r`n Groups: $($Groups -join ",")" -Server $Edge -Target $this.Computer.HostName -Credential $Cred.UserName
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        Write-Warning "Computer is already a member of one of the groups provided"
                        continue
                    } 
                    catch {
                        Show-MessageBox -Message "Failed to add groups on EDGE Domain Controller. $_" -Title 'Error'
                        Write-Log -Error -ID 9 -Message "Failed to add groups on EDGE Domain Controller.`r`n Error:`r`n $_" -Server $Edge -Target $this.Computer.HostName -Credential $Cred.UserName
                    }
                }
                else {
                    try {
                        Add-ADPrincipalGroupMembership -Identity $HostName -MemberOf $Groups -Server $Core -Credential $Cred -Confirm:$False -WarningAction "SilentlyContinue"
                        Show-MessageBox -Message 'Groups added successfully on Core' -Title 'Success'
                        Write-Log -ID 9 -Message "Groups added successfully on Core.`r`n Groups: $($Groups -join ",")" -Server $Core -Target $this.Computer.HostName -Credential $Cred.UserName
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        Write-Warning "Computer is already a member of one of the groups provided"
                        continue
                    } 
                    catch {
                        Show-MessageBox -Message "Failed to add groups on CORE Domain Controller. $_" -Title 'Error'
                        Write-Log -Error -ID 109 -Message "Failed to add groups on a Core Domain Controller.`r`n Error:`r`n $_" -Server $Core -Target $this.Computer.HostName -Credential $Cred.UserName
                    }
                }
            })

        $GroupForm.ShowDialog()
    }

    [void] RemoveCompGroups() {
        $HostName = ($this.Computer.HostName -split "\.")[0] + '$'
        $Core = ($this.Computer.OU -split "/")[0]
        $IsSchoolComputer = $this.IsSchoolComputer()
        $CentreCode = ($this.Computer.HostName -replace '[a-z]').Substring(0, 4)
        if ($IsSchoolComputer) {
            $Edge = $this.GetDomainController()
        }
        $CompGroups = $this.Computer.Groups -split "`r`n"
        

        $Cred = Get-PrivilegedCredential -Domain $Core

        if (!$Cred) {
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            Write-Log -Error -ID 100 -Message "No groups selected or entered, 'Add' pressed." -Target $this.Computer.HostName -Credential $Cred.UserName
            Return
        }

        $GroupForm = New-Object System.Windows.Forms.Form
        $GroupForm.Text = "Remove Groups"
        $GroupForm.Size = New-Object System.Drawing.Size(350, 350)
        $GroupForm.StartPosition = "CenterScreen"

        $Label = New-Object System.Windows.Forms.Label
        $Label.Location = New-Object System.Drawing.Size(10, 10)
        $Label.Size = New-Object System.Drawing.Size(260, 30)
        $Label.Text = "Removable groups below."
        $GroupForm.Controls.Add($Label)

        $ListBox = New-Object System.Windows.Forms.ListBox
        $ListBox.Location = New-Object System.Drawing.Size(10, 40)
        $ListBox.Size = New-Object System.Drawing.Size(240, 220)
        $ListBox.SelectionMode = 'MultiExtended'
        $GroupForm.Controls.Add($ListBox)

        $RemoveGroupsButton = New-Object System.Windows.Forms.Button
        $RemoveGroupsButton.Location = New-Object System.Drawing.Size(90, 260)
        $RemoveGroupsButton.Size = New-Object System.Drawing.Size(100, 20)
        $RemoveGroupsButton.Text = "Remove Groups"
        $GroupForm.AcceptButton = $RemoveGroupsButton
        $GroupForm.Controls.Add($RemoveGroupsButton)

        foreach ($Result in $CompGroups) {
            [void] $ListBox.Items.Add("$Result")
        }

        $RemoveGroupsButton.Add_Click( {
                $Groups = $null
                $Groups = $ListBox.SelectedItems -split "`r`n"

            
                if ($Groups -eq $null) {
                    Show-MessageBox -Message "No groups selected. $_" -Title 'Error' 
                    Write-Log -Error -ID 110 -Message "No groups selected or entered, 'Remove' pressed." -Target $this.Computer.HostName -Credential $Cred.UserName
                }
                
                if ($IsSchoolComputer -eq $False) {
                    try {
                        Remove-ADPrincipalGroupMembership -Identity $Hostname -MemberOf $Groups -Server $Core -Credential $Cred -Confirm:$False
                        Show-MessageBox -Message "Groups removed successfully from CORE Domain Controller" -Title 'Success'
                        Write-Log -ID 10 -Message "Groups removed successfully from CORE Domain Controller.`r`n Groups: $($Groups -join ",")" -Server $Core -Target $this.Computer.HostName -Credential $Cred.UserName
                    }
                    catch {
                        Show-MessageBox -Message "Failed to remove groups from CORE Domain Controller. $_" -Title 'Error'
                        Write-Log -IOD 110 -Message "Failed to remove groups from CORE Domain Controller.`r`n Error:`r`n $_" -Server $Core -Target $this.Computer.HostName -Credential $Cred.UserName
                    }
                }
                else {
                    try {
                        Remove-ADPrincipalGroupMembership -Identity $HostName -MemberOf $Groups -Server $Edge -Credential $Cred -Confirm:$False
                        Remove-ADPrincipalGroupMembership -Identity $Hostname -MemberOf $Groups -Server $Core -Credential $Cred -Confirm:$False
                        Show-MessageBox -Message "Groups removed successfully on CORE and EDGE" -Title 'Success'
                        Write-Log -ID 10 -Message "Groups removed successfully on CORE and EDGE.`r`n Groups: $($Groups -join ",")" -Server $Edge -Target $this.Computer.HostName -Credential $Cred.UserName
                    }
                    catch {
                        Show-MessageBox -Message "Failed to remove groups from EDGE Domain Controller. $_" -Title 'Error'
                        Write-Log -ID 110 -Message "Failed to remove groups from EDGE Domain Controller.`r`n Error:`r`n $_" -Server $Edge -Target $this.Computer.HostName -Credential $Cred.UserName
                    }
                }
            })

        $GroupForm.ShowDialog()
    }
}