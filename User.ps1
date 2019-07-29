Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Import-Module ActiveDirectory

class WhoAccount {
    $Account

    WhoAccount($account) {
        $this.Account = $account
    }

    [void] AppendToRTB(
        [System.Windows.Forms.RichTextBox]$RTB
    ) {
        Append-ObjectToRTB -RTB $RTB -Object $this.Account
    }

    [void] CopyToClipboard() {
        Set-Clipboard $this.ToString()
    }

    [void] Disable() {

        $Core = $this.Account.Domain
    
        $Cred = Get-PrivilegedCredential -Domain $Core
    
        if (!$Cred) {
            Write-Log -Error -ID 100 -Message "No credentials entered"
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            Return
        }

        if ($this.Account.Domain -ne $Global:svrCORP) {
            $Edge = $this.GetDomainController()

            try {
                Disable-ADAccount -Identity $this.Account.Username -Server $Core -Credential $Cred
                Disable-ADAccount -Identity $this.Account.Username -Server $Edge -Credential $Cred
                Show-MessageBox -Message 'Account disabled on Edge and Core Domain Controller' -Title 'Success'
                Write-Log -ID 4 -Message 'User account successfully disabled on Edge and Core' -Server $Edge -Target $this.Account.Username -Credential $Cred.UserName
            }
            catch {
                Show-MessageBox -Message "Failed to disable account on Edge and Core Domain Controller. $_" -Title 'Error'
                Write-Log -Error -ID 104 -Message "Failed to disable account on Edge and Core Domain Controller. $_" -Server $Edge -Target $this.Account.Username -Credential $Cred.UserName
            }
        }
        else {
            try {
                Disable-ADAccount -Identity $this.Account.Username -Server $Core -Credential $Cred
                Show-MessageBox -Message 'Account disabled on a Core Domain Controller' -Title 'Success'
                Write-Log -ID 4 -Message 'User account successfully disabled on Core' -Server $Core -Target $this.Account.Username -Credential $Cred.UserName
            }
            catch {
                Show-MessageBox -Message "Failed to disable account on a Core Domain Controller. $_" -Title 'Error'
                Write-Log -Error -ID 104 -Message "Failed to disable account on a Core Domain Controller. $_" -Server $Core -Target $this.Account.Username -Credential $Cred.UserName
            }
        }
    }

    [void] EditADCore() {
        Open-ActiveDirectory -Server $this.Account.Domain
    }

    [void] EditADEdge() {
        Open-ActiveDirectory -Server ($this.GetDomainController())
    }

    [bool] IsSchoolAccount() {
        return ($this.Account.Domain -ne $global:svrCORP)
    }

    [void] Enable() {

        $Core = $this.Account.Domain
    
        $Cred = Get-PrivilegedCredential -Domain $Core
    
        if (!$Cred) {
            Write-Log -Error -ID 100 -Message "No credentials entered"
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            Return
        }
    
        if ($this.IsSchoolAccount()) {
            $Edge = $this.GetDomainController()
            try {
                Enable-ADAccount -Identity $this.Account.Username -Server $Core -Credential $Cred
                Enable-ADAccount -Identity $this.Account.Username -Server $Edge -Credential $Cred
                Show-MessageBox -Message 'Account enabled on Edge and Core Domain Controller' -Title 'Success'
                Write-Log -ID 3 -Message 'User account successfully enabled on Edge and Core' -Server $Edge -Target $this.Account.Username -Credential $Cred.UserName
            }
            catch {
                Show-MessageBox -Message "Failed to enable account on Edge and Core Domain Controller. $_" -Title 'Error'
                Write-Log -Error -ID 103 -Message "Failed to enable account on Edge and Core Domain Controller. $_" -Server $Edge -Target $this.Account.Username -Credential $Cred.UserName
            }
        }
        else {
            try {
                Enable-ADAccount -Identity $this.Account.Username -Server $Core -Credential $Cred
                Show-MessageBox -Message 'Account enabled on Core Domain Controller' -Title 'Success'
                Write-Log -ID 3 -Message 'User account successfully enabled on Core' -Server $Core -Target $this.Account.Username -Credential $Cred.UserName
            }
            catch {
                Show-MessageBox -Message "Failed to enable account on Core Domain Controller. $_" -Title 'Error'
                Write-Log -Error -ID 103 -Message "Failed to enable account on Core Domain Controller. $_" -Server $Core -Target $this.Account.Username -Credential $Cred.UserName
            }
        }
    }

    [string] GetDomainController() {
        $CentreCode = $this.Account.EQCentreCode
        return @(Get-ADDomainController -Filter { Name -like "*$CentreCode*" } -Server $this.Account.Domain | Select-Object -ExpandProperty HostName)[0]
    }

    [void] ResetPassword() {

        $Username = $this.Account.Username
        $Core = $this.Account.Domain

        $Today = Get-Date
        $Password = $Today.DayOfWeek.ToString() + "." + $Today.Day.ToString()
    
        $Cred = Get-PrivilegedCredential -Domain $Core
    
        if (!$Cred) {
            Write-Log -Error -ID 100 -Message "No Credentials entered"
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            return
        }

        try {
            # Set Password
            Set-ADAccountPassword -Identity $Username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -Credential $Cred -Server $Core

            # Require password change on logon
            Set-ADUser -Identity $Username -ChangePasswordAtLogon $true -Credential $Cred -Server $Core

            # Unlock account on Core
            Unlock-ADAccount -Identity $Username -Server $Core -Credential $Cred

            # If account is a school account, unlock on Edge
            if ($this.IsSchoolAccount()) {
                $Edge = $this.GetDomainController()
                Unlock-ADAccount -Identity $Username -Server $Edge -Credential $Cred
            }

            Write-Log -ID 5 -Message "Reset the target account's password." -Target $Username -Credential $Cred.UserName -Server $Core
            Show-MessageBox -Message "Password reset to $Password" -Title "Success!"

        }
        catch {
            Write-Log -Error -ID 105 -Message "Something went wrong trying to reset the target account's password. $_" -Target $Username -Credential $Cred.UserName -Server $Core
            Show-MessageBox -Message "Something went wrong. $_" -Title "Error!"
        }
    
    }

    [string] ToString() {
        $Text = ""
        $this.Account.PSObject.Properties | ForEach-Object {
            if (($_.Name -ne "Employee Number") -and ($_.Name -ne "Street Address") -and ($_.Name -ne "Department") -and ($_.Name -ne "Office")) {
                $Text += $_.Name + ': ' + $_.Value + [System.Environment]::NewLine
            }
        }
        Return $Text
    }

    [void] Unlock() {

        $Core = $this.Account.Domain

        $Cred = Get-PrivilegedCredential -Domain $Core
    
        if (!$Cred) {
            Write-Log -Error -ID 100 -Message "No credentials entered"
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            return
        }

        if ($this.IsSchoolAccount()) {
            $Edge = $this.GetDomainController()
            try {
                Unlock-ADAccount -Identity $this.Account.Username -Server $Core -Credential $Cred
                Unlock-ADAccount -Identity $this.Account.Username -Server $Edge -Credential $Cred
                Show-MessageBox -Message 'Account unlocked on Edge and Core Domain Controller' -Title 'Success'
                Write-Log -ID 2 -Message 'User account successfully unlocked on Edge and Core' -Server $Edge -Target $this.Account.Username -Credential $Cred.UserName
            }
            catch {
                Show-MessageBox -Message "Failed to unlock account on Edge and Core Domain Controller. $_" -Title 'Error'
                Write-Log -Error -ID 102 -Message "Failed to unlock account on Edge and Core Domain Controller. $_" -Server $Edge -Target $this.Account.Username -Credential $Cred.UserName
            }
        }
        else {
            try {
                Unlock-ADAccount -Identity $this.Account.Username -Server $Core -Credential $Cred
                Show-MessageBox -Message 'Account unlocked on a Core Domain Controller' -Title 'Success'
                Write-Log -ID 2 -Message 'User account successfully unlocked on Core' -Server $Core -Target $this.Account.Username -Credential $Cred.UserName
            }
            catch {
                Show-MessageBox -Message "Failed to unlock account on a Core Domain Controller. $_" -Title 'Error'
                Write-Log -Error -ID 102 -Message "Failed to unlock account on a Core Domain Controller. $_" -Server $Core -Target $this.Account.Username -Credential $Cred.UserName
            }
        }
    }

    [void] AddUserGroups() {
        $Username = $this.Account.Username
        $Core = $this.Account.Domain
        if ($this.IsSchoolAccount()) {
            $Edge = $this.GetDomainController()
        }
        $CentreCode = $this.Account.EQCentreCode
        $UserGroups = $this.Account."Groups + DLs" -split "`r`n"

        $Cred = Get-PrivilegedCredential -Domain $Core
        $WarningPreference = "SilentlyContinue"
    
        if (!$Cred) {
            Write-Log -Error -ID 100 -Message "No Credentials entered"
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            return
        }

        $Principal = @($CentreCode + "BG", $CentreCode + "BG", $CentreCode + "GG_UsrAdmin", $CentreCode + "GG_UsrPrincipal", $CentreCode + "GG_UsrOffice", $CentreCode + "GG_UsrStaff", $CentreCode + "GG_UsrFinance", $CentreCode + "GG_APP_Sims_C", $CentreCode + "GG_UsrTeachers", $CentreCode + "GG_MobileUsers", $CentreCode + "GG_OutlookUsers")
        $AdminOfficer = @($CentreCode + "BG", $CentreCode + "GG_UsrStaff", $CentreCode + "GG_UsrOffice", $CentreCode + "GG_UsrAdmin", $CentreCode + "GG_OutlookUsers")
        $BSM = @($CentreCode + "BG", $CentreCode + "GG_UsrStaff", $CentreCode + "GG_UsrOffice", $CentreCode + "GG_UsrAdmin", $CentreCode + "GG_UsrFinance", $CentreCode + "GG_APP_Sims_C", $CentreCode + "GG_UsrAide", $CentreCode + "GG_OutlookUsers")
        $HOD = @($CentreCode + "BG", $CentreCode + "GG_UsrStaff", $CentreCode + "GG_UsrTeachers", $CentreCode + "GG_UsrHOD", $CentreCode + "GG_MobileUsers", $CentreCode + "GG_OutlookUsers")
        $Teacher = @($CentreCode + "BG", $CentreCode + "GG_UsrStaff", $CentreCode + "GG_UsrTeachers", $CentreCode + "GG_MobileUsers", $CentreCode + "GG_OutlookUsers")

        $GroupForm = New-Object System.Windows.Forms.Form
        $GroupForm.Text = "Add Groups"
        $GroupForm.Size = New-Object System.Drawing.Size(300, 300)
        $GroupForm.StartPosition = "CenterScreen"

        $TemplateLabel = New-Object System.Windows.Forms.Label
        $TemplateLabel.Location = New-Object System.Drawing.Size(10, 10)
        $TemplateLabel.Size = New-Object System.Drawing.Size(260, 30)
        $TemplateLabel.Text = "Group templates below, see the guide for more info. Groups added based on Centre Code."
        $GroupForm.Controls.Add($TemplateLabel)

        $TeacherCheckbox = New-Object System.Windows.Forms.Checkbox 
        $TeacherCheckbox.Location = New-Object System.Drawing.Size(10, 40) 
        $TeacherCheckbox.Size = New-Object System.Drawing.Size(90, 20)
        $TeacherCheckbox.Text = "Teacher"
        $GroupForm.Controls.Add($TeacherCheckbox)

        $HODCheckbox = New-Object System.Windows.Forms.CheckBox
        $HODCheckbox.Location = New-Object System.Drawing.Size(10, 60)
        $HODCheckbox.Size = New-Object System.Drawing.Size(90, 20)
        $HODCheckbox.Text = "HOD"
        $GroupForm.Controls.Add($HODCheckbox)

        $BSMCheckbox = New-Object System.Windows.Forms.CheckBox
        $BSMCheckbox.Location = New-Object System.Drawing.Size(10, 80)
        $BSMCheckbox.Size = New-Object System.Drawing.Size(90, 20)
        $BSMCheckbox.Text = "BSM"
        $GroupForm.Controls.Add($BSMCheckbox)

        $AOCheckbox = New-Object System.Windows.Forms.CheckBox
        $AOCheckbox.Location = New-Object System.Drawing.Size(100, 40)
        $AOCheckbox.Size = New-Object System.Drawing.Size(100, 20)
        $AOCheckbox.Text = "Admin Officer"
        $GroupForm.Controls.Add($AOCheckbox)

        $PrincipalCheckbox = New-Object System.Windows.Forms.CheckBox
        $PrincipalCheckbox.Location = New-Object System.Drawing.Size(100, 60)
        $PrincipalCheckbox.Size = New-Object System.Drawing.Size(100, 20)
        $PrincipalCheckbox.Text = "Principal"
        $GroupForm.Controls.Add($PrincipalCheckbox)

        $GroupTextLabel = New-Object System.Windows.Forms.Label
        $GroupTextLabel.Location = New-Object System.Drawing.Size(10, 120)
        $GroupTextLabel.Size = New-Object System.Drawing.Size(260, 30)
        $GroupTextLabel.Text = "Add groups here. Separate each group with a semicolon ;"
        $GroupForm.Controls.Add($GroupTextLabel)

        $GroupTextBox = New-Object System.Windows.Forms.TextBox
        $GroupTextBox.Location = New-Object System.Drawing.Size(10, 160)
        $GroupTextBox.Size = New-Object System.Drawing.Size(260, 100)
        $GroupTextBox.Text = $null
        $GroupForm.Controls.Add($GroupTextBox)

        $AddGroupsButton = New-Object System.Windows.Forms.Button
        $AddGroupsButton.Location = New-Object System.Drawing.Size(90, 200)
        $AddGroupsButton.Size = New-Object System.Drawing.Size(100, 20)
        $AddGroupsButton.Text = "Add Groups"
        $GroupForm.AcceptButton = $AddGroupsButton
        $GroupForm.Controls.Add($AddGroupsButton)

        $AddGroupsButton.Add_Click( {
                if ($TeacherCheckbox.Checked -eq $true) {
                    $Groups = $null
                    $Groups = -split $Teacher
                }
                elseif ($HODCheckbox.Checked -eq $true) {
                    $Groups = $null
                    $Groups = -split $HOD
                }
                elseif ($BSMCheckbox.Checked -eq $true) {
                    $Groups = $null
                    $Groups = -split $BSM
                }
                elseif ($AOCheckbox.Checked -eq $true) {
                    $Groups = $null
                    $Groups = -split $AdminOfficer
                }
                elseif ($PrincipalCheckbox.Checked -eq $true) {
                    $Groups = $null
                    $Groups = -split $Principal
                }
                elseif ($GroupTextBox.Text -ne $null) {
                    $Groups += $GroupTextBox.Text -split ";"
                }

                if ($Groups -eq $null) {
                    Show-MessageBox -Message "No Groups selected. $_" -Title 'Error'
                    Write-Log -Error -ID 106 -Message "No groups selected or entered, 'Add' pressed." -Target $this.Account.Name -Credential $Cred.UserName
                    Return
                }
    
                if ($this.IsSchoolAccount() -eq $False) {
                    try {
                        Add-ADPrincipalGroupMembership -Identity $Username -MemberOf $Groups -Server $Core -Credential $Cred -WarningAction "SilentlyContinue"
                        Show-MessageBox -Message 'Groups added successfully on Core' -Title 'Success'
                        Write-Log -ID 6 -Message "Groups added successfully on Core.`r`n Groups: $($Groups -join ",")" -Server $Core -Target $this.Account.Name -Credential $Cred.UserName
                    }
                    catch {
                        Show-MessageBox -Message "Failed to add groups on CORE Domain Controller. $_" -Title 'Error'
                        Write-Log -Error -ID 106 -Message "Failed to add groups on a Core Domain Controller.`r`n Error:`r`n $_" -Server $Core -Target $this.Account.Name -Credential $Cred.UserName
                    }
    
                }
                else {
                    try {
                        Add-ADPrincipalGroupMembership -Identity $Username -MemberOf $Groups -Server $Core -Credential $Cred -WarningAction "SilentlyContinue"
                        Add-ADPrincipalGroupMembership -Identity $Username -MemberOf $Groups -Server $Edge -Credential $Cred -WarningAction "SilentlyContinue"
                        Show-MessageBox -Message "Groups added successfully on CORE and EDGE" -Title 'Success'
                        Write-Log -ID 6 -Message "Groups added successfully on CORE and EDGE.`r`n Groups: $($Groups -join ",")" -Server $Edge -Target $this.Account.Name -Credential $Cred.UserName
                    } 
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        Write-Warning "User already a member of one of the groups provided"
                        continue
                    } 
                    catch {
                        Show-MessageBox -Message "$_.Error" -Title 'Error'
                        Write-Log -Error -ID 106 -Message "Failed to add groups on EDGE Domain Controller.`r`n Error:`r`n $_" -Server $Edge -Target $this.Account.Name -Credential $Cred.UserName
                    }
                }
            })
    
        $GroupForm.ShowDialog()
    }

    [void] RemoveUserGroups() {
        $Username = $this.Account.Username
        $Core = $this.Account.Domain
        $Edge = $this.GetDomainController()
        $UserGroups = $this.Account."Groups + DLs" -split "`r`n"

        $Cred = Get-PrivilegedCredential -Domain $Core
    
        if (!$Cred) {
            Write-Log -Error -ID 100 -Message "No credentials entered."
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            return
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

        foreach ($Result in $UserGroups) {
            [void] $ListBox.Items.Add("$Result")
        }

        $RemoveGroupsButton.Add_Click( {
                $Groups = $null
                $Groups = $ListBox.SelectedItems -split "`r`n"

                if ($Groups -eq $null) {
                    Show-MessageBox -Message "$_" -Title "Error"
                    Write-Log -Error -ID 107 -Message "$Env:USERNAME attempted to remove groups. No groups selected or entered, 'Remove Groups' pressed." -Server $Core -Target $this.Account.Username -Credential $Cred.UserName
                }

                if ($this.IsSchoolAccount() -eq $False) {
                    Remove-ADPrincipalGroupMembership -Identity $Username -MemberOf $Groups -Server $Core -Credential $Cred -Confirm:$False
                    Show-MessageBox -Message "Groups removed successfully on Core" -Title 'Success'
                    Write-Log -ID 7 -Message "$Env:USERNAME removed groups on Core.`r`n Groups: $($Groups -join ",")" -Server $Core -Target $this.Account.Username -Credential $Cred.UserName

                }
                else {
                    Remove-ADPrincipalGroupMembership -Identity $Username -MemberOf $Groups -Server $Edge -Credential $Cred -Confirm:$False
                    Remove-ADPrincipalGroupMembership -Identity $Username -MemberOf $Groups -Server $Core -Credential $Cred -Confirm:$False
                    Show-MessageBox -Message "Groups removed successfully on Core and Edge" -Title 'Success'
                    Write-Log -ID 7 -Message "$Env:USERNAME removed groups on Core and Edge.`r`n Groups: $($Groups -join ",")" -Server $Edge -Target $this.Account.Username -Credential $Cred.UserName
                }
            })

        $GroupForm.ShowDialog()
    }

    [void] UserDOB() {
        $iRegisterURI = "https://iRegister.det.qld.gov.au/Identity/OnBehalfOf?username="
        $Username = $this.Account.Username
        $URI = $iRegisterURI + $Username
        $iRegister = Invoke-WebRequest $URI -Proxy "http://proxy-corp.corp.qed.qld.gov.au" -ProxyUseDefaultCredentials -UseDefaultCredentials

        if ($iRegister -match '<tr class="identity-field">
                <td class="identity-field-label">
                    <span title="Date of birth">Date of birth:</span>
                </td>
                <td class="identity-field-value">
(?<Title>.+)                    <div class="identity-field-actions">'
        ) {
            $DOB = $Matches.Title
            Show-MessageBox -Message "$DOB" -Title 'Success'
            Write-Log -ID 8 -Message "$Env:USERNAME gathered date of birth." -Target $this.Account.Username
        }
        else {
            $DOB = $null
            Show-MessageBox -Message 'No Date of birth found for user' -Title 'Error'
            Write-Log -Error -ID 108 -Message "$Env:USERNAME failed to gather date of birth" -Target $this.Account.Username
        }

    }
    <#
    [void] MoveUser() {
        $Username = $this.Account.Username
        $Core = $this.Account.Domain
        if ($Core -ne $Global:svrCORP) {
            $Edge = $this.GetDomainController()
        }
        $AccountType = $this.Account."Staff/Student"

        $Cred = Get-PrivilegedCredential -Domain $Core
    
        if (!$Cred) {
            Write-Log -Error -ID 100 -Message "No credentials entered."
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            return
        }

        $Title = "Move user to site"
        $Msg = "Enter site code to move user to"

        $SiteCode = [Microsoft.VisualBasic.Interaction]::InputBox($Msg, $Title)

        if ($Core -ne $Global:svrCORP) {
            $OUs = @{
                "StaffLFOU" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Staff Accounts'" -Server $Core | Select-Object DistinguishedName),
                "Other Lost and Found" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Other Accounts'" -Server $Core | Select-Object DistinguishedName),
                "Student Lost and Found" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Student Accounts'" -Server $Core | Select-Object DistinguishedName),
                "Staff OU" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Staff'" -Server $Core | Select-Object DistinguishedName),
                "Other OU" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Other'" -Server $Core | Select-Object DistinguishedName),
                "Student OU" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Students'" -Server $Core | Select-Object DistinguishedName)
            }
        } else {
            $OUs = @{
                "User Lost and Found" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*User Accounts'" -Server $Core | Select-Object DistinguishedName),
                "Other Lost and Found" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Other Accounts'" -Server $Core | Select-Object DistinguishedName),
                "Non-Policy User OU" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Non Policy User'" -Server $Core | Select-Object DistinguishedName),
                "Policy User OU" = (Get-ADOrganizationalUnit -Filter "Name -like '*$SiteCode*' -and Name -like '*Policy User'" -Server $Core | Select-Object DistinguishedName)
            }
        }

        $MoveForm = New-Object System.Windows.Forms.Form
        $MoveForm.Text = "Move Users"
        $MoveForm.Size = New-Object System.Drawing.Size(350, 350)
        $MoveForm.StartPosition = "CenterScreen"

        $Label = New-Object System.Windows.Forms.Label
        $Label.Location = New-Object System.Drawing.Size(10, 10)
        $Label.Size = New-Object System.Drawing.Size(260, 30)
        $Label.Text = "OUs to move user below:"
        $MoveForm.Controls.Add($Label)

        $ListBox = New-Object System.Windows.Forms.ListBox
        $ListBox.Location = New-Object System.Drawing.Size(10, 40)
        $ListBox.Size = New-Object System.Drawing.Size(240, 220)
        $ListBox.SelectionMode = 'MultiExtended'
        $MoveForm.Controls.Add($ListBox)

        $MoveUserButton = New-Object System.Windows.Forms.Button
        $MoveUserButton.Location = New-Object System.Drawing.Size(90, 260)
        $MoveUserButton.Size = New-Object System.Drawing.Size(100, 20)
        $MoveUserButton.Text = "Move User"
        $MoveForm.AcceptButton = $MoveUserButton
        $MoveForm.Controls.Add($MoveUserButton)

        foreach ($Result in $OUs) {
            [void] $ListBox.Items.Add($Result.Name)
        }

        $MoveUserButton.Add_Click({
            $OU = $OUs | Where-Object {$_.Name -eq $ListBox.SelectedItems} | Select-Object Values
            Write-Host $OU
        })
        
        $MoveForm.ShowDialog()
    }
    #>
}