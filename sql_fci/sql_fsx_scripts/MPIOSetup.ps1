[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$DomainNetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$AdminSecret,

    [Parameter(Mandatory=$true)]
    [string]$DomainDNSName

)

$HostName = hostname
$HostAddress = "{0}.{1}" -f $HostName, $DomainDNSName

# Getting Password from Secrets Manager for AD Admin User
$AdminUser = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $AdminSecret).SecretString
$ClusterAdminUser = $DomainNetBIOSName + '\' + $AdminUser.UserName
# Creating Credential Object for Administrator
$Credentials = (New-Object PSCredential($ClusterAdminUser,(ConvertTo-SecureString $AdminUser.Password -AsPlainText -Force)))


Invoke-Command -ScriptBlock {
    winrm quickconfig -quiet
    Install-WindowsFeature -name Multipath-IO -Restart
} -Credential $Credentials -ComputerName $HostAddress -Authentication credssp 