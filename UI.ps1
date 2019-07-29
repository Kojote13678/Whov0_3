Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Import-Module ActiveDirectory

$redStrings = @(
    "Discontinued",
    "Suspended",
    "Account is disabled",
    "Account is locked out",
    "Account has expired",
    "Password has expired"
)

$greenStrings = @(
    "Active",
    "Account is enabled",
    "Account is not locked out",
    "Account has not expired",
    "Password has not expired",
    "No Expiry Date Set"
)

function CloseCurrentTab {
    param([System.Windows.Forms.TabControl]$tabControl)
    $index = $tabControl.SelectedIndex
    $tabControl.TabPages.Remove($tabControl.SelectedTab)
    $tabControl.SelectedIndex = $index
}

function CloseAllTabs {
    param($tabControl)
    $tabControl.TabPages.Clear()
}

function New-RTB {
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock = [System.Windows.Forms.DockStyle]::Fill
    $rtb.ReadOnly = $true
    $rtb.Font = New-Object System.Drawing.Font('Consolas', 10)
    $rtb.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $rtb.BackColor = [System.Drawing.Color]::White
    $rtb.DetectUrls = $false
    $rtb.Text = ''

    return $rtb
}

function Copy-ToClipboard {
    param($object)
    $text = ''
    $object.PSObject.Properties | ForEach-Object {
        if (($_.Name -ne "Employee Number") -and ($_.Name -ne "Street Address") -and ($_.Name -ne "Department") -and ($_.Name -ne "Office")) {
        $text += $_.Name + ': ' + $_.Value + [System.Environment]::NewLine
        }
    Set-Clipboard $text
    }
}

function Append-ObjectToRTB {
    param (
        $object,
        [System.Windows.Forms.RichTextBox]$RTB
    )

    $maxLength = 0
    $result.PSObject.Properties | ForEach-Object {
        $length = $_.Name.toString().Length
        if ($length -gt $maxLength) {
            $maxLength = $length
        }
    }

    $boldFont = New-Object System.Drawing.Font($RTB.Font, [System.Drawing.FontStyle]::Bold)
    $regularFont = New-Object System.Drawing.Font($RTB.Font, [System.Drawing.FontStyle]::Regular)

    $result.PSObject.Properties | ForEach-Object {
        $name = "$($_.Name):".PadRight($maxLength + 2)
        $value = "$($_.Value)"

        if ($value.Contains("`n")) {
            $value = "`n$($value)"
        }

        if (($name.Contains("Staff")) -or ($name.Contains("Last Logon Date"))) {
            $value = "$($value)`n"
        }

        

        $RTB.SelectionFont = $boldFont
        $RTB.AppendText($name)

        $RTB.SelectionFont = $regularFont
        if ($redStrings.Contains($value)) {
            $RTB.SelectionBackColor = [System.Drawing.Color]::Red
            $RTB.SelectionColor = [System.Drawing.Color]::White
        }

        if ($greenStrings.Contains($value)) {
            $RTB.SelectionBackColor = [System.Drawing.Color]::Green
            $RTB.SelectionColor = [System.Drawing.Color]::White
        } 

        $RTB.AppendText($value)
        $RTB.AppendText("`n")

        $RTB.SelectionBackColor = $RTB.BackColor
        $RTB.SelectionColor = $RTB.ForeColor
    }
}
    

function New-MainTab {

    param(
        [string]$headerText,
        [ScriptBlock]$searchFunction
    )
    
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = $headerText
    $tab.BackColor = [System.Drawing.Color]::White

    $table = New-Object System.Windows.Forms.TableLayoutPanel
    $table.Dock = [System.Windows.Forms.DockStyle]::Fill
    $table.RowCount = 2
    $table.ColumnCount = 2
    $table.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $table.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Percent, 100)) | Out-Null
    $table.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent, 100)) | Out-Null
    $table.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::AutoSize)) | Out-Null

    $tab.Controls.Add($table)

    $searchBox = New-Object System.Windows.Forms.TextBox

    $searchBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $searchBox.add_KeyDown({
        if ($_.KeyCode -eq "Enter") {
            $searchFunction.Invoke()
        }
    }.GetNewClosure())
    $table.Controls.Add($searchBox, 0, 0)

    $searchButton = New-Object System.Windows.Forms.Button
    $searchButton.Text = 'Search'
    $searchButton.Dock = [System.Windows.Forms.DockStyle]::Fill
    $searchButton.add_Click($searchFunction)
    $table.Controls.Add($searchButton, 1, 0)

    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
    $table.Controls.Add($tabControl, 0, 1)
    $table.SetColumnSpan($tabControl, 2)

    $closeTab = $Function:CloseCurrentTab
    $closeAll = $Function:CloseAllTabs

    $contextMenu = New-Object System.Windows.Forms.ContextMenu
    $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close Current Tab', {$closeTab.Invoke($tabControl)}.GetNewClosure(), [System.Windows.Forms.Shortcut]::CtrlW))) | Out-Null
    $contextMenu.MenuItems.Add((New-Object System.Windows.Forms.MenuItem('Close All Tabs', {$closeAll.Invoke($tabControl)}.GetNewClosure(), [System.Windows.Forms.Shortcut]::CtrlShiftW))) | Out-Null
    $tab.ContextMenu = $contextMenu
    $tabControl.ContextMenu = $contextMenu
    
    return $tab, $searchBox, $tabControl
}

function Hide-Console {
    # Hide PowerShell Console
    Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '

    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0)
}

function Show-MessageBox {
    param (
        [string]$Message,
        [string]$Title = "Attention"
    )

    [System.Windows.Forms.MessageBox]::Show($Message, $Title)
}