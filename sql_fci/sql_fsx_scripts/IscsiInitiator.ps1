[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$DomainNetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$AdminSecret

)

$HostName = hostname

# Getting Password from Secrets Manager for AD Admin User
$AdminUser = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $AdminSecret).SecretString
$ClusterAdminUser = $DomainNetBIOSName + '\' + $AdminUser.UserName
# Creating Credential Object for Administrator
$Credentials = (New-Object PSCredential($ClusterAdminUser,(ConvertTo-SecureString $AdminUser.Password -AsPlainText -Force)))

Invoke-Command -ScriptBlock {
    Write-Output "Iscsi Setup started"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Start-service -Name msiscsi
    Set-Service -Name msiscsi -StartupType Automatic
    Write-Output "Iscsi Setup completed"
} -Credential $Credentials -ComputerName $HostName -Authentication credssp