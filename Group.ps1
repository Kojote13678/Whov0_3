Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Import-Module ActiveDirectory

Class WhoGroup {
    $Group

    WhoGroup($Group) {
        $this.Group = $Group
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
        $this.Group.PSObject.Properties | ForEach-Object {
            $Text += $_.Name + ': ' + $_.Value + [System.Environment]::NewLine
        }
        Return $Text
    }

    [void] GetDomainController() {
        $Core = (($this.Group.CanonicalName) -split "/")[0] 
        $CentreCode = $this.Group."Group Name".Substring(0, 4)
        @(Get-ADDomainController -Filter { Name -like "*$CentreCode*" } -Server $Core | Select-Object -ExpandProperty HostName)[0]

    }

    [void] EditADCore() {
        $Core = (($this.Group.CanonicalName) -split "/")[0] 
        Open-ActiveDirectory -Server $Core
    }

    [void] EditADEdge() {
        $CentreCode = $this.Group."Group Name".Substring(0, 4)
        $Core = (($this.Group.CanonicalName) -split "/")[0]
        $Edge = @(Get-ADDomainController -Filter { Name -like "*$CentreCode*" } -Server $Core | Select-Object -ExpandProperty HostName)[0]

        if ($Edge -ne $null) {
            Open-ActiveDirectory -Server $Edge
        }
        else {
            Show-MessageBox -Message "No DC can be found using $CentreCode as a centre code" -Title 'Error'
        }   
    }

    [bool] IsSchoolGroup() {
        return ($this.Group.Domain -ne $global:svrCORP)
    }

    [void]AddGroupGroups() {
        $Groupname = $this.Group."Group Name"
        $Core = ($this.Group.CanonicalName -split "/")[0]
        $CentreCode = $this.Group."Group Name".Substring(0, 4)
        if ($this.IsSchoolGroup()) {
            $Edge = $this.GetDomainController()
        }

        $Cred = Get-PrivilegedCredential -Domain $Core

        if (!$Cred) {
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            Write-Log -Error -ID 100 -Message "No groups selected or entered, 'Add' pressed." -Target $this.Group."Group Name" -Credential $Cred.UserName
            Return
        }

        $GroupForm = New-Object System.Windows.Forms.Form
        $GroupForm.Text = "Add Groups and Members"
        $GroupForm.Size = New-Object System.Drawing.Size(300, 300)
        $GroupForm.StartPosition = "CenterScreen"

        $MemberTextLabel = New-Object System.Windows.Forms.Label
        $MemberTextLabel.Location = New-Object System.Drawing.Size(10, 40)
        $MemberTextLabel.Size = New-Object System.Drawing.Size(260, 30)
        $MemberTextLabel.Text = "Add members here. Separate each member with a semicolon ;"
        $GroupForm.Controls.Add($MemberTextLabel)

        $MemberTextBox = New-Object System.Windows.Forms.TextBox
        $MemberTextBox.Location = New-Object System.Drawing.Size(10, 80)
        $MemberTextBox.Size = New-Object System.Drawing.Size(260, 100)
        $MemberTextBox.Text = $null
        $GroupForm.Controls.Add($MemberTextBox)

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
        $AddGroupsButton.Text = "Add"
        $GroupForm.AcceptButton = $AddGroupsButton
        $GroupForm.Controls.Add($AddGroupsButton)

        $AddGroupsButton.Add_Click( {
                $Groups = $null
                $Groups = $GroupTextBox.Text -split ";"
                $Members = $null
                $Members = $MemberTextBox.Text -split ";"

                if (($Groups -ne $null) -and ($this.IsSchoolGroup())) {
                    try {
                        Add-ADPrincipalGroupMembership -Identity $Groupname -MemberOf $Groups -Server $Core -Credential $Cred
                        Add-ADPrincipalGroupMembership -Identity $Groupname -MemberOf $Groups -Server $Edge -Credential $Cred
                        Show-MessageBox -Message "Groups Added successfully on CORE and EDGE" -Title "Success"
                        Write-Log -ID 11 -Message "$Env:USERNAME successfully added groups to $Groupname.`r`n Groups Added: $($Groups -join ",")" -Target $this.Group."Group Name" -Credential $Cred.UserName -Server $Edge
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        Write-Warning "group already a member of one of the groups provided"
                        continue
                    } 
                    catch {
                        Show-MessageBox -Message "$_.Error" -Title 'Error'
                        Write-Log -Error -ID 111 -Message "Failed to add groups on CORE and EDGE Domain Controller.`r`n Error:`r`n $_" -Server $Edge -Target $this.Group."Group Name" -Credential $Cred.UserName
                    }
                }
                elseif (($Members -ne $null) -and ($this.IsSchoolGroup())) {
                    try {
                        Add-ADGroupMember -Identity $Groupname -Members $Members -Server $Core -Credential $Cred -Confirm:$False
                        Add-ADGroupMember -Identity $Groupname -Members $Members -Server $Edge -Credential $Cred -Confirm:$False
                        Show-MessageBox -Message "Members removed successfully on CORE and EDGE" -Title "Success"
                        Write-Log -ID 111 -Message "$Env:USERNAME successfully removed Members from $Groupname.`r`n Members removed: $($Members -join ",")" -Target $this.Group."Group Name" -Credential $Cred.UserName -Server $Edge
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        Write-Warning "Member already attached to the group provided"
                        continue
                    }
                    catch {
                        Show-MessageBox -Message "Failed to add members on CORE and EDGE. $_" -Title 'Error'
                        Write-Log -Error -ID 111 -Message "Failed to add members on CORE and EDGE Domain Controller.`r`n Error:`r`n $_" -Server $Edge -Target $this.Group."Group Name" -Credential $Cred.UserName
                    }
                }
                elseif (($Groups -ne $null) -and ($this.IsSchoolGroup() -eq $False)) {
                    try {
                        Add-ADPrincipalGroupMembership -Identity $Groupname -MemberOf $Groups -Server $Core -Credential $Cred
                        Show-MessageBox -Message "Groups added successfully on Core" -Title "Success"
                        Write-Log -ID 11 -Message "$Env:USERNAME successfully added groups to $Groupname.`r`n Groups Added: $($Groups -join ",")" -Server $Core -Target $this.Group."Group Name" -Credential $Cred.UserName
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        Write-Warning "Group already a member of one of the groups provided"
                        continue
                    }
                    catch {
                        Show-MessageBox -Message "Failed to add groups on CORE. $_" -Title 'Error'
                        Write-Log -Error -ID 111 -Message "Failed to add groups on CORE Domain Controller.`r`n Error:`r`n $_" -Server $Core -Target $this.Group."Group Name" -Credential $Cred.UserName
                    }   
                }
                elseif (($Members -ne $null) -and ($this.IsSchoolGroup() -eq $False)) {
                    try {
                        Add-ADGroupMember -Identity $Groupname -Members $Members -Server $Core -Credential $Cred -Confirm:$False
                        Show-MessageBox -Message "Members removed successfully on CORE" -Title "Success"
                        Write-Log -ID 111 -Message "$Env:USERNAME successfully removed Members from $Groupname.`r`n Members removed: $($Members -join ",")" -Server $Core -Target $this.Group."Group Name" -Credential $Cred.UserName
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        Write-Warning "Member already attached to the group provided"
                        continue
                    }
                    catch {
                        Show-MessageBox -Message "Failed to add members on CORE. $_" -Title 'Error'
                        Write-Log -Error -ID 111 -Message "Failed to add members on CORE.`r`n Error:`r`n $_" -Server $Core -Target $this.Group."Group Name" -Credential $Cred.UserName
                    }
                }
            })

        $GroupForm.ShowDialog()
    }

    [void] RemoveGroupGroups() {
        $Groupname = $this.Group."Group Name"
        $Core = ($this.Group.CanonicalName -split "/")[0]
        $CentreCode = $this.Group."Group Name".Substring(0, 4)
        $GroupGroups = $this.Group."Groups + DLs" -split "`r`n"
        $GroupMembers = $this.Group.Members -split "`r`n"
        if ($this.IsSchoolGroup()) {
            $Edge = $this.GetDomainController()
        }

        $Cred = Get-PrivilegedCredential -Domain $Core

        if (!$Cred) {
            Show-MessageBox -Message 'No credentials entered. Please try again.' -Title 'Error'
            Write-Log -Error -ID 100 -Message "No groups selected or entered, 'Add' pressed." -Target $this.Group."Group Name" -Credential $Cred.UserName
            Return
        }

        $GroupForm = New-Object System.Windows.Forms.Form
        $GroupForm.Text = "Remove Groups and Members"
        $GroupForm.Size = New-Object System.Drawing.Size(300, 600)
        $GroupForm.StartPosition = "CenterScreen"

        $Label = New-Object System.Windows.Forms.Label
        $Label.Location = New-Object System.Drawing.Size(10, 10)
        $Label.Size = New-Object System.Drawing.Size(260, 30)
        $Label.Text = "Removable groups and members below below."
        $GroupForm.Controls.Add($Label)

        $MembersListBox = New-Object System.Windows.Forms.ListBox
        $MembersListBox.Location = New-Object System.Drawing.Size(10, 40)
        $MembersListBox.Size = New-Object System.Drawing.Size(240, 220)
        $MembersListBox.SelectionMode = 'MultiExtended'
        $GroupForm.Controls.Add($MembersListBox)

        $GroupsListBox = New-Object System.Windows.Forms.ListBox
        $GroupsListBox.Location = New-Object System.Drawing.Size(10, 280)
        $GroupsListBox.Size = New-Object System.Drawing.Size(240, 220)
        $GroupsListBox.SelectionMode = 'MultiExtended'
        $GroupForm.Controls.Add($GroupsListBox)

        $RemoveGroupsButton = New-Object System.Windows.Forms.Button
        $RemoveGroupsButton.Location = New-Object System.Drawing.Size(90, 520)
        $RemoveGroupsButton.Size = New-Object System.Drawing.Size(100, 20)
        $RemoveGroupsButton.Text = "Remove"
        $GroupForm.AcceptButton = $RemoveGroupsButton
        $GroupForm.Controls.Add($RemoveGroupsButton)

        foreach ($Member in $GroupMembers) {
            [void] $MembersListBox.Items.Add("$Member")
        }

        foreach ($Result in $GroupGroups) {
            [void] $GroupsListBox.Items.Add("$Result")
        }

        $RemoveGroupsButton.Add_Click( {
                $Groups = $null
                $Groups = $GroupsListBox.SelectedItems -split "`r`n"
                $Members = $null
                $Members = $MembersListBox.SelectedItems -split "`r`n"

                foreach ($Member in $Members) {
                    $Result = @() 
                    $Result += @($Member -split "\(")[1] -replace "\)"
                    $Members = $Result -split "`r`n"
                }

                if (($Groups -ne $null) -and ($this.IsSchoolGroup())) {
                    Remove-ADPrincipalGroupMembership -Identity $Groupname -MemberOf $Groups -Server $DomainController -Credential $Cred -Confirm:$False
                    Remove-ADPrincipalGroupMembership -Identity $Groupname -MemberOf $Groups -Server $Server -Credential $Cred -Confirm:$False
                    Show-MessageBox -Message "Groups removed successfully on CORE and EDGE" -Title "Success"
                    Write-Log -ID 12 -Message "$Env:USERNAME successfully removed groups from $Groupname.`r`n Groups removed: $($Groups -join ",")" -Target $this.Group."Group Name" -Credential $Cred.UserName -Server $Edge

                }
                elseif (($Members -ne $null) -and ($this.IsSchoolGroup())) {
                    Remove-ADGroupMember -Identity $Groupname -Members $Members -Server $DomainController -Credential $Cred -Confirm:$False
                    Remove-ADGroupMember -Identity $Groupname -Members $Members -Server $Server -Credential $Cred -Confirm:$False
                    Show-MessageBox -Message "Members removed successfully on CORE and EDGE" -Title "Success"
                    Write-Log -ID 12 -Message "$Env:USERNAME successfully removed Members from $Groupname.`r`n Members removed: $($Members -join ",")" -Target $this.Group."Group Name" -Credential $Cred.UserName -Server $Edge

                }
                elseif (($Groups -ne $null) -and ($this.IsSchoolGroup() -eq $False)) {
                    Remove-ADPrincipalGroupMembership -Identity $Groupname -MemberOf $Groups -Server $Server -Credential $Cred -Confirm:$False
                    Show-MessageBox -Message "Groups removed successfully on CORE" -Title "Success"
                    Write-Log -ID 12 -Message "$Env:USERNAME successfully removed Groups from $Groupname.`r`n Groups removed: $($Groups -join ",")" -Target $this.Group."Group Name" -Credential $Cred.UserName -Server $Core

                }
                elseif (($Members -ne $null) -and ($this.IsSchoolGroup() -eq $False)) {
                    Remove-ADGroupMember -Identity $Groupname -Members $Members -Server $Server -Credential $Cred -Confirm:$False
                    Show-MessageBox -Message "Members removed successfully on CORE" -Title "Success"
                    Write-Log -ID 12 -Message "$Env:USERNAME successfully removed Members from $Groupname.`r`n Members removed: $($Members -join ",")" -Target $this.Group."Group Name" -Credential $Cred.UserName -Server $Core

                }
                elseif (($Groups -eq $null) -and ($Members -eq $null)) {
                    Show-MessageBox -Message "$_" -Title "Error"
                    Write-Log -ID 12 -Message "$Env:USERNAME attempted to remove groups/members. No groups/members entered, 'Remove' pressed." -Target $this.Group."Group Name" -Credential $Cred.UserName
                }
            })

        $GroupForm.ShowDialog()

    }
}