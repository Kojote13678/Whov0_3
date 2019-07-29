Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

Import-Module ActiveDirectory
Write-Host "Running Search.ps1"
. '.\Search.ps1'

Write-Host "Running UI.ps1"
. '.\UI.ps1'

Write-Host "Running User.ps1"
. '.\User.ps1'

Write-Host "Running Computer.ps1"
. '.\Computer.ps1'

Write-Host "Running Group.ps1"
. '.\Group.ps1'

Write-Host "Running Logging.ps1"
. '.\Logging.ps1'

Write-Host "Running Util.ps1"
. '.\Util.ps1'

Write-Host "Initialising Event Log..."
Initialize-EventLog

#--------------------------------
# Global Variables
#--------------------------------
Write-Host "Setting up global variables..."

$global:Debug = $true

$global:svrCORP = "corp.qed.qld.gov.au"
$global:svrGBN = "gbn.eq.edu.au"
$global:svrSUN = "sun.eq.edu.au"
$global:svrSOC = "soc.eq.edu.au"
$global:svrMTN = "mtn.eq.edu.au"
$global:svrWBB = "wbb.eq.edu.au"
$global:svrNOQ = "noq.eq.edu.au"
$global:svrDDS = "dds.eq.edu.au"
$global:svrFNQ = "fnq.eq.edu.au"
$global:svrFCW = "fcw.eq.edu.au"
$global:svrMYW = "myw.eq.edu.au"
$global:svrRES = "res.eq.edu.au"

$global:Domains = @($svrCORP, $svrRES, $svrGBN, $svrSUN, $svrSOC, $svrMTN, $svrWBB, $svrNOQ, $svrDDS, $svrFNQ, $svrFCW, $svrMYW)

Write-Host "Getting Corp Priviledged Account... " -NoNewline
$global:CORPPrivAccount = Get-HighestAccount -Server $svrCORP
Write-Host "Found $global:CORPPrivAccount"

Write-Host "Getting School Priviledged Account... " -NoNewline
$global:SchoolPrivAccount = Get-HighestAccount -Server $svrGBN
Write-Host "Found $global:SchoolPrivAccount"

#--------------------------------
# End Global Variables
#--------------------------------

if (!$Debug) { 
    Write-Host "Hiding console..."
    Hide-Console 
}
[System.Windows.Forms.Application]::EnableVisualStyles()

function ChangeLog {
    $Title = "Change Log"
    $Version = "3.1.3"
    $ChangeHeader = "Changes for " + "$Version" + ":"
    $ChangeMessage = 
    "This is a test for our program"
    $Changes = $ChangeHeader + "`r`n" + $ChangeMessage

    $ChangeLog = Test-Path "D:\WhoChangeLog.txt"

    if (!$ChangeLog) {
        New-Item -Path "D:\" -Name "WhoChangeLog.txt" -ItemType "file" -Value $Changes
        $ChangeForm = New-Object System.Windows.Forms.Form
        $ChangeForm.Text = "$Title"
        $ChangeForm.Size = New-Object System.Drawing.Size(600, 600)
        $ChangeForm.StartPosition = "CenterScreen"

        $Label = New-Object System.Windows.Forms.Label
        $Label.Location = New-Object System.Drawing.Size(10, 10)
        $Label.Size = New-Object System.Drawing.Size(260, 30)
        $Label.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
        $Label.Text = "$ChangeHeader"
        $ChangeForm.Controls.Add($Label)

        $RichTB = New-Object System.Windows.Forms.RichTextBox
        $RichTB.Location = New-Object System.Drawing.Size(10, 40)
        $RichTB.Size = New-Object System.Drawing.Size(565, 450)
        $RichTB.Font = New-Object System.Drawing.Font("Arial", 10)
        $RichTB.Text = "$ChangeMessage"
        $ChangeForm.Controls.Add($RichTB)

        $OKButton = New-Object System.Windows.Forms.Button
        $OKButton.Location = New-Object System.Drawing.Size(240, 510)
        $OKButton.Size = New-Object System.Drawing.Size(100, 30)
        $OKButton.Text = "OK"
        $ChangeForm.AcceptButton = $OKButton
        $ChangeForm.Controls.Add($OKButton)

        $OKButton.Add_Click( {
                $ChangeForm.Close()
            })

        $ChangeForm.ShowDialog()
    } else {
        Write-Host "User has already viewed Change Log"
    }

    
}
ChangeLog

function RefreshUser {
    param ($tab, $user)
    $searchText = $user.Username
    SearchUser $tab $searchText

    Write-Log -ID 1 -Message "$ENV:USERNAME refreshed search for $searchText."
}

function RefreshComputer {
    param ($tab, $computer)
    $searchText = (($computer.HostName) -split "\.")[0]
    SearchComputer $tab $searchText

    Write-Log -ID 1 -Message "$ENV:USERNAME refreshed search for $searchText."
}

function RefreshGroup {
    param ($tab, $group)
    $searchText = $group."Group Name"
    SearchGroup $tab $searchText

    Write-Log -ID 1 -Message "$ENV:USERNAME refreshed search for $searchText."
}

function SearchNewUser {
    $searchText = $userSearchBox.Text
    $userSearchBox.Text = ''

    Write-EventLog -LogName Who -Source WhoApplication -EntryType Information -EventId 1 -Message "$ENV:USERNAME searched for $searchText."

    $tab = New-Object System.Windows.Forms.TabPage

    SearchUser $tab $searchText

    $userTabControl.TabPages.Add($tab)
    $userTabControl.SelectedTab = $tab
}

function SearchUser {

    param ($tab, $searchText)

    $results = Search-WhoUser $searchText

    Write-EventLog -LogName Who -Source WhoApplication -EntryType Information -EventId 1 -Message "$ENV:USERNAME searched for $searchText."
    
    $tab.Text = $searchText

    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill

    $contextMenu = New-Object System.Windows.Forms.ContextMenu
    $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close Current Tab', { CloseCurrentTab $userTabControl }, [System.Windows.Forms.Shortcut]::CtrlW)))
    $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close All Tabs', { CloseAllTabs $userTabControl }, [System.Windows.Forms.Shortcut]::CtrlShiftW)))
    $tab.ContextMenu = $contextMenu
    $tabControl.ContextMenu = $contextMenu

    foreach ($result in $results) {

        $resultTab = New-Object System.Windows.Forms.TabPage
        $resultTab.Text = $result.Domain.split('.')[0].toUpper()

        $rtb = New-RTB

        Append-ObjectToRTB $result $rtb
        
        $resultTab.Controls.Add($rtb)

        $Account = [WhoAccount]::new($result)

        $contextMenu = New-Object System.Windows.Forms.ContextMenu
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Copy All', { $Account.CopyToClipboard() }.GetNewClosure())))
        $refresh = $function:RefreshUser
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Refresh', { $refresh.Invoke($tab, $result) }.GetNewClosure(), [System.Windows.Forms.Shortcut]::CtrlR)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close Current Tab', { CloseCurrentTab $userTabControl }, [System.Windows.Forms.Shortcut]::CtrlW)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close All Tabs', { CloseAllTabs $userTabControl }, [System.Windows.Forms.Shortcut]::CtrlShiftW)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('-')))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Add Groups', { $Account.AddUserGroups() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Edit Active Directory - CORE', { $Account.EditADCore() }.GetNewClosure())))
        if ($Account.IsSchoolAccount()) {
            $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Edit Active Directory - EDGE', { $Account.EditADEdge() }.GetNewClosure())))
        }
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Enable Account', { $Account.Enable() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Get DOB', { $Account.UserDOB() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Move User', { $Account.MoveUser() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Reset Password', { $Account.ResetPassword() }.getNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Unlock Account', { $Account.Unlock() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('-')))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Disable Account', { $Account.Disable() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Remove Groups', { $Account.RemoveUserGroups() }.GetNewClosure())))
        $rtb.ContextMenu = $contextMenu

        $tabControl.TabPages.Add($resultTab)

    }

    $tab.Controls.Clear()
    $tab.Controls.Add($tabControl)
}

function SearchComputer {
    
    $searchText = $computerSearchBox.Text
    $computerSearchBox.Text = ''

    $results = Search-WhoComputer $searchText

    $Output = $results | Export-Csv "D:\WhoComputerOutput.csv" -NoTypeInformation -Force

    Write-EventLog -LogName Who -Source WhoApplication -EntryType Information -EventId 1 -Message "$ENV:USERNAME searched for $searchText"
   

    foreach ($result in $results) {

        $tab = New-Object System.Windows.Forms.TabPage
        $tab.Text = $searchText

        $rtb = New-RTB

        Append-ObjectToRTB $result $rtb
        
        $tab.Controls.Add($rtb)

        $Computer = [WhoComputer]::new($result)

        $contextMenu = New-Object System.Windows.Forms.ContextMenu
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Copy All', { $Computer.CopyToClipboard() }.GetNewClosure())))
        $refreshC = $function:RefreshComputer
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Refresh', { $refreshC.Invoke($tab, $result) }.GetNewClosure(), [System.Windows.Forms.Shortcut]::CtrlR)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close Current Tab', { CloseCurrentTab $computerTabControl }, [System.Windows.Forms.Shortcut]::CtrlW)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close All Tabs', { CloseAllTabs $computerTabControl }, [System.Windows.Forms.Shortcut]::CtrlShiftW)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Export Tabs to CSV', { $Output })))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('-')))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Add AD Groups', { $Computer.AddCompGroups() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Edit AD Core', { $Computer.EditADCore() }.GetNewClosure())))
        if ($Computer.IsSchoolComputer()) {
            $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Edit AD Edge', { $Computer.EditADEdge() }.GetNewClosure())))
        }
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Get Computer Information', { $Computer.ComputerInfo() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Ping', { $Computer.Ping() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('-')))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Remove AD Groups', { $Computer.RemoveCompGroups() }.GetNewClosure())))
        $rtb.ContextMenu = $contextMenu
        $computerTabControl.TabPages.Add($tab)
        $computerTabControl.SelectedTab = $tab

    }
}

function SearchGroup {
    
    $searchText = $groupSearchBox.Text
    $groupSearchBox.Text = ''

    $results = Search-WhoGroup $searchText

    Write-EventLog -LogName Who -Source WhoApplication -EntryType Information -EventId 1 -Message "$ENV:USERNAME searched for $searchText."
    
    foreach ($result in $results) {

        $tab = New-Object System.Windows.Forms.TabPage
        $tab.Text = $searchText

        $rtb = New-RTB

        Append-ObjectToRTB $result $rtb
        
        $tab.Controls.Add($rtb)

        $Group = [WhoGroup]::new($result)

        $contextMenu = New-Object System.Windows.Forms.ContextMenu
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Copy All', { $Group.CopyToClipboard() }.GetNewClosure())))
        $refresh = $function:RefreshGroup
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Refresh', { $refresh.Invoke($tab, $result) }.GetNewClosure(), [System.Windows.Forms.Shortcut]::CtrlR)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close Current Tab', { CloseCurrentTab $groupTabControl }, [System.Windows.Forms.Shortcut]::CtrlW)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close All Tabs', { CloseAllTabs $groupTabControl }, [System.Windows.Forms.Shortcut]::CtrlShiftW)))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('-')))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Add AD Groups', { $Group.AddGroupGroups() }.GetNewClosure())))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Edit AD Core', { $Group.EditADCore() }.GetNewClosure())))
        if ($Group.IsSchoolGroup()) {
            $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Edit AD Edge', { $Group.EditADEdge() }.GetNewClosure())))
        }
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('-')))
        $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Remove AD Groups', { $Group.RemoveGroupGroups() }.GetNewClosure())))
        $rtb.ContextMenu = $contextMenu

        $groupTabControl.TabPages.Add($tab)
        $groupTabControl.SelectedTab = $tab

    }
}




$window = New-Object System.Windows.Forms.Form
$window.Text = 'ITSC Who'
$window.Width = 600
$window.Height = 800

$mainTabControl = New-Object System.Windows.Forms.TabControl
$mainTabControl.Dock = [System.Windows.Forms.DockStyle]::Fill

$mainUserTab, $userSearchBox, $userTabControl = New-MainTab 'User' $Function:SearchNewUser
$mainTabControl.TabPages.Add($mainUserTab)

$mainComputerTab, $computerSearchBox, $computerTabControl = New-MainTab 'Computer' $Function:SearchComputer
$mainTabControl.TabPages.Add($mainComputerTab)

$mainGroupTab, $groupSearchBox, $groupTabControl = New-MainTab 'Group' $Function:SearchGroup
$mainTabControl.TabPages.Add($mainGroupTab)

$window.Controls.Add($mainTabControl)


$window.ShowDialog()
