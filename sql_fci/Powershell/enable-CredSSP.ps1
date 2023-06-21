[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$DomainDNSName

)


$HostName = hostname
$HostAddress = "*.{0}" -f $DomainDNSName

$DomainAdminName = "admin"
$Member = "{0}\{1}" -f $DomainDNSName, $DomainAdminName
Add-LocalGroupMember -Group "Administrators" -Member $Member

$spn = "WSMAN/{0}" -f $HostAddress
$account = "{0}\{1}" -f $DomainDNSName, $HostName

setspn -S $spn $account
# setspn -S WSMAN/*.$DomainDNSName $HostAddress

# Disable-WSmanCredSSP -Role Server
# Disable-WSmanCredSSP -Role Client

Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Item WSMan:\localhost\Client\TrustedHosts  * -Force
Restart-Service WinRM -Force

Enable-WSManCredSSP -Role "Server" -Force
Enable-WSManCredSSP -Role "Client" -DelegateComputer $HostAddress -Force
Restart-Service WinRM -Force

# New-Item hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly
# New-ItemProperty hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value "wsman/*.$DomainDNSName" -Force
