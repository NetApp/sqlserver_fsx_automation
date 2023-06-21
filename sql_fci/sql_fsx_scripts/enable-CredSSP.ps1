[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$DomainDNSName

)

$DomainAdminName = "admin"
$Member = "{0}\{1}" -f $DomainDNSName, $DomainAdminName
Add-LocalGroupMember -Group "Administrators" -Member $Member

$HostName = hostname
$HostAddress = "{0}.{1}" -f $HostName, $DomainDNSName

Enable-PSRemoting -SkipNetworkProfileCheck -Force

Enable-WSManCredSSP -Role "Server" -Force
Enable-WSManCredSSP -Role "Client" -DelegateComputer $HostAddress -Force

Get-Service -ComputerName $HostName -Name WinRM | Restart-Service