[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$DomainDNSName

)


$HostName = hostname
$HostAddress = "{0}.{1}" -f $HostName, $DomainDNSName
Enable-WSManCredSSP -Role "Server" -Force
Enable-WSManCredSSP -Role "Client" -DelegateComputer $HostAddress -Force


# [CmdletBinding()]
# param(

#     [Parameter(Mandatory=$true)]
#     [string]$DomainDNSName

# )


# $HostName = hostname
# $HostAddress = "{0}.{1}" -f $HostName, $DomainDNSName

# # Specify the SPN to create
# $spn = "WSMAN/$HostName"

# Enable-WSManCredSSP -Role "Server" -Force
# Enable-WSManCredSSP -Role "Client" -DelegateComputer $HostAddress -Force

# # Configure the local Group Policy to allow fresh credentials with NTLM-only server authentication
# $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
# if (!(Test-Path $policyPath)) { New-Item $policyPath -Force | Out-Null }
# Set-ItemProperty $policyPath "AllowFreshCredentials" -Value 1
# Set-ItemProperty $policyPath "ConcatenateDefaults_AllowFreshCredentials" -Value 1
# Set-ItemProperty $policyPath "AllowFreshCredentialsWhenNTLMOnly" -Value 1

# # Configure the local computer to allow delegation to the remote server using NTLM-only authentication
# Invoke-Command -ComputerName $HostName -ScriptBlock {
#     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowFreshCredentials" -Value "1"
#     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "ConcatenateDefaults_AllowFresh" -Value "1"
# }

# Set-Item -Path "WSMan:\localhost\Client\AllowFreshCredentials" -Value 1
# Set-Item -Path "WSMan:\localhost\Client\Auth\CredSSP" -Value 1
# Set-Item -Path "WSMan:\localhost\Client\TrustedHosts" -Value $computerName -Force

# # Create the SPN on the remote server using setspn.exe
# Invoke-Command -ComputerName $HostName -ScriptBlock {
#     param($spn)
#     setspn -s $spn $env:COMPUTERNAME
# } -ArgumentList $spn




