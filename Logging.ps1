function Initialize-EventLog {

    if ((Get-EventLog -list).Log -notcontains "Who") {
        Invoke-Command -ComputerName LocalHost -Credential "-$ENV:USERNAME" -ScriptBlock {New-EventLog -LogName Who -Source WhoApplication}
    }

    Write-EventLog -LogName Who -Source WhoApplication -EventId 0 -EntryType Information -Message "Who application has started. User starting the application is $ENV:USERDOMAIN\$ENV:USERNAME on $ENV:COMPUTERNAME"
}

function Write-Log {
    param (
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][int]$ID,
        [switch]$Error,
        [string]$Server,
        [string]$Target,
        [string]$Credential
    )

    if ($Error) {
        $entryType = [System.Diagnostics.EventLogEntryType]::Error
    } else {
        $entryType = [System.Diagnostics.EventLogEntryType]::Information
    }

    if ($Server) {
        $Message += "`r`nServer: $Server"
    }

    if ($Target) {
        $Message += "`r`nThe target of this action was $Target"
    }

    if ($Credential) {
        $Message += "`r`nThe account used to perform this action was $Credential"
    }

    $Message += "`r`nThe workstation used to perform this action was $ENV:COMPUTERNAME"

    Write-EventLog -LogName Who -Source WhoApplication -EntryType $entryType -EventId $ID -Message $Message

}