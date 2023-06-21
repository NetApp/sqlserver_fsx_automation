# Script to setup the primary FCI node
# To RUN: .\myscript.ps1 -instanceId "i-0123456789abcdefg" -adDomain "mydomain.com" -adUser "myusername" -adPassword "mypassword" -lambdaFunctionName "mylambdafunction"

Install-Module AWS.Tools.EC2 -Force
Import-Module AWS.Tools.EC2
Import-Module AWS.Tools.PowerShell

# Input parameters
param(
    [string]$instanceId,
    [string]$adDomain,
    [string]$adUser,
    [string]$adPassword,
    [string]$lambdaFunctionName,
    [string]$DomainNetBIOSName,
)

# Task 1: Get IP of EC2 instance from instance ID
$privateStr = ""
$resultStr = ""
$ip = Get-EC2Instance -InstanceId $instanceId 
$pIP = $ip.instances[0].PrivateIpAddress
$privateStr = "{0};{1}" -f $privateStr, $pIP
$IPs = $ip.instances[0].NetworkInterfaces.PrivateIpAddresses
$ip1 = $IPs[1].PrivateIpAddress
$ip2 = $IPs[2].PrivateIpAddress
$resultStr = "{0};{1};{2}" -f $resultStr, $ip1, $ip2

# Task 2: Update SSM agent
Invoke-WebRequest https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe -OutFile $env:USERPROFILE\Desktop\SSMAgent_latest.exe
Start-Process -FilePath $env:USERPROFILE\Desktop\SSMAgent_latest.exe -ArgumentList "/S"

# Update-SSMAgent -InstanceIds $instanceId -Force

# Task 3: Initialize disk
& "C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Scripts\\InitializeDisks.ps1"

# Task 4: Install DSC modules
# "Setting up Powershell Gallery to Install DSC Modules"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# "Installing the needed Powershell DSC modules"
Install-Module -Name ComputerManagementDsc
Install-Module -Name "xFailOverCluster"
Install-Module -Name PSDscResources
Install-Module -Name xSmbShare
Install-Module -Name "xActiveDirectory"

# "Disabling Windows Firewall"
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

# "Creating Directory for DSC Public Cert"
$directoryPath = "C:\AWSQuickstart\publickeys"

if (Test-Path -Path $directoryPath) {
    Remove-Item -Path $directoryPath -Recurse
}
New-Item -Path $directoryPath -ItemType directory

# "Setting up DSC Certificate to Encrypt Credentials in MOF File"
$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'AWSQSDscEncryptCert' -HashAlgorithm SHA256
$cert | Export-Certificate -FilePath "C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer" -Force


# Task 5: Set LCM config
# This block sets the LCM configuration to what we need for setup
[DSCLocalConfigurationManager()]
configuration LCMConfig
{
    Node 'localhost' {
        Settings {
            RefreshMode = 'Push'
            ActionAfterReboot = 'StopConfiguration'
            RebootNodeIfNeeded = $false
            CertificateId = $DscCertThumbprint
        }
    }
}

$DscCertThumbprint = [string](get-childitem -path cert:\LocalMachine\My | where { $_.subject -eq "CN=AWSQSDscEncryptCert" }).Thumbprint

# Generates MOF File for LCM
LCMConfig -OutputPath 'C:\AWSQuickstart\LCMConfig'

# Sets LCM Configuration to MOF generated in previous command
Set-DscLocalConfigurationManager -Path 'C:\AWSQuickstart\LCMConfig' 

# $configurationData = @{
#     AllNodes = @(
#         @{
#             NodeName = 'localhost'
#             PSDscAllowPlainTextPassword = $true
#         }
#     )
# }

# Set-DscLocalConfigurationManager -Path .\MyConfig -ConfigurationData $configurationData

# Task 6: Join instance to Active Directory
$securePassword = ConvertTo-SecureString $adPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($adUser, $securePassword)

$computerName = $env:COMPUTERNAME
$domain = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Domain

if ($domain -ne $null) {
    Write-Host "Computer '$computerName' is joined to domain: $domain"
}
else {
    Add-Computer -DomainName $adDomain -Credential $credential
    Restart-Computer -Force 
}


# Task 7: Enable CredSSP
$HostName = hostname
$HostAddress = "{0}.{1}" -f $HostName, $DomainDNSName
Enable-WSManCredSSP -Role "Server" -Force
Enable-WSManCredSSP -Role "Client" -DelegateComputer $HostAddress -Force

# Task 8: Initialize iSCSI initiator with MPIO
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
} -Credential $Credentials -ComputerName $HostAddress -Authentication credssp

# Task 9: Get IQN value
$iqn = (Get-InitiatorPort).NodeAddress

# Task 10: MPIO Setup
Invoke-Command -ScriptBlock {
    winrm quickconfig -quiet
    Install-WindowsFeature -name Multipath-IO -Restart
} -Credential $Credentials -ComputerName $HostAddress -Authentication credssp 

# Task 11: Run Lambda function
Invoke-AWSPowerShellLambda -FunctionName $lambdaFunctionName -Payload $iqn

# Task 12: Mount iSCSI disk
$diskNumber = Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Select-Object -ExpandProperty Number
$volume = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -Confirm:$false

# Task 13: Creating WSFC config
$DscCertThumbprint = (get-childitem -path cert:\LocalMachine\My | where { $_.subject -eq "CN=AWSQSDscEncryptCert" }).Thumbprint
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName="*"
            CertificateFile = "C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer"
            Thumbprint = $DscCertThumbprint
            PSDscAllowDomainUser = $true
        },
        @{
            NodeName = 'localhost'
        }
    )
}

Configuration WSFCNode1Config {
    param(
        [PSCredential] $Credentials
    )

    Import-Module -Name PSDscResources
    Import-Module -Name xFailOverCluster
    Import-Module -Name xActiveDirectory

    Import-DscResource -Module PSDscResources
    Import-DscResource -ModuleName xFailOverCluster
    Import-DscResource -ModuleName xActiveDirectory

    Node 'localhost' {
        WindowsFeature RSAT-AD-PowerShell {
            Name = 'RSAT-AD-PowerShell'
            Ensure = 'Present'
        }

        WindowsFeature AddFailoverFeature {
            Ensure = 'Present'
            Name   = 'Failover-clustering'
            DependsOn = '[WindowsFeature]RSAT-AD-PowerShell'
        }

        WindowsFeature AddRemoteServerAdministrationToolsClusteringFeature {
            Ensure    = 'Present'
            Name      = 'RSAT-Clustering-Mgmt'
            DependsOn = '[WindowsFeature]AddFailoverFeature'
        }

        WindowsFeature AddRemoteServerAdministrationToolsClusteringPowerShellFeature {
            Ensure    = 'Present'
            Name      = 'RSAT-Clustering-PowerShell'
            DependsOn = '[WindowsFeature]AddRemoteServerAdministrationToolsClusteringFeature'
        }

        WindowsFeature AddRemoteServerAdministrationToolsClusteringCmdInterfaceFeature {
            Ensure    = 'Present'
            Name      = 'RSAT-Clustering-CmdInterface'
            DependsOn = '[WindowsFeature]AddRemoteServerAdministrationToolsClusteringPowerShellFeature'
        }

        xCluster CreateCluster {
            Name                          =  $ClusterName
            StaticIPAddress               =  $WSFCNode1PrivateIP2
            DomainAdministratorCredential =  $Credentials
            DependsOn                     = '[WindowsFeature]AddRemoteServerAdministrationToolsClusteringCmdInterfaceFeature'
        }

        if ($FileServerNetBIOSName) {
        xClusterQuorum 'SetQuorumToNodeAndFileShareMajority' {
            IsSingleInstance = 'Yes'
            Type             = 'NodeAndFileShareMajority'
            Resource         = 'G:'
            DependsOn        = '[xCluster]CreateCluster'
        }
        } else {
            xClusterQuorum 'SetQuorumToNodeMajority' {
                IsSingleInstance = 'Yes'
                Type             = 'NodeMajority'
                DependsOn        = '[xCluster]CreateCluster'
            }
        }
    }
}

WSFCNode1Config -OutputPath 'C:\AWSQuickstart\WSFCNode1Config' -ConfigurationData $ConfigurationData -Credentials $Credentials

function DscStatusCheck () {
    $LCMState = (Get-DscLocalConfigurationManager).LCMState
    if ($LCMState -eq 'PendingConfiguration' -Or $LCMState -eq 'PendingReboot') {
        'returning 3010, should continue after reboot'
        exit 3010
    } else {
      'Completed'
    }
}

Start-DscConfiguration 'C:\AWSQuickstart\WSFCNode1Config' -Wait -Verbose -Force

DscStatusCheck

# Task 14: Configure MAD permissions
$wsfcCN = $wsfcName
Invoke-Command -scriptblock {
	$computer = get-adcomputer $Using:wsfcCN
	$discard,$OU = $computer -split ',',2
	$acl = get-acl "ad:$OU"
	$acl.access #to get access right of the OU
	$sid = [System.Security.Principal.SecurityIdentifier] $computer.SID
	$objectguid1 = new-object Guid bf967a86-0de6-11d0-a285-00aa003049e2 # is the rightsGuid for Create Computer Object class
	$inheritedobjectguid = new-object Guid bf967aa5-0de6-11d0-a285-00aa003049e2 # is the schemaIDGuid for the OU
	$identity = [System.Security.Principal.IdentityReference] $SID
	$adRights = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild"
	$adRights2 = [System.DirectoryServices.ActiveDirectoryRights] "ReadProperty"
	$type = [System.Security.AccessControl.AccessControlType] "Allow"
	$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
	$ace1 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectGuid1,$inheritanceType,$inheritedobjectguid
	$ACE2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights2,$type,$inheritanceType
	$acl.AddAccessRule($ace1)
	$acl.AddAccessRule($ACE2)
	Set-acl -aclobject $acl "ad:$OU"
} -Credential $Credentials -ComputerName $HostAddress -Authentication credssp

# Task 15: Prepare FCI and download SQL server ISO
#Retrieving MSSQL service account
$SqlUser = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $SqlUserSecret).SecretString
$SqlUserName = $DomainNetBIOSName + '\' + $SqlUser.UserName
$SqlUserPassword = $SqlUser.Password

#Acquiring MSSQL installation media from S3
$mediaIsoPath = 'c:\mssql-setup-media\en_sql_server_2019_developer_x64_dvd_baea4195.iso'
$mediaExtractPath = 'C:\SQLinstallmedia'

Copy-S3Object -BucketName $MSSQLMediaBucket -Key $MSSQLMediaKey -LocalFile $mediaIsoPath

#Mounting and extracting installation media files
New-Item -Path $mediaExtractPath -ItemType Directory
$mountResult = Mount-DiskImage -ImagePath $mediaIsoPath -PassThru
$volumeInfo = $mountResult | Get-Volume
$driveInfo = Get-PSDrive -Name $volumeInfo.DriveLetter
Copy-Item -Path ( Join-Path -Path $driveInfo.Root -ChildPath '*' ) -Destination $mediaExtractPath -Recurse
Dismount-DiskImage -ImagePath $mediaIsoPath

#Prepare FCI installation
$arguments = '/ACTION="PrepareFailoverCluster" /IAcceptSQLServerLicenseTerms="True" /IACCEPTROPENLICENSETERMS="False" /SUPPRESSPRIVACYSTATEMENTNOTICE="True" /ENU="True" /QUIET="True" /UpdateEnabled="False" /USEMICROSOFTUPDATE="False" /SUPPRESSPAIDEDITIONNOTICE="True" /UpdateSource="MU" /FEATURES=SQLENGINE,REPLICATION,FULLTEXT,DQ /HELP="False" /INDICATEPROGRESS="False" /X86="False" /INSTANCENAME="MSSQLSERVER" /INSTALLSHAREDDIR="C:\Program Files\Microsoft SQL Server" /INSTALLSHAREDWOWDIR="C:\Program Files (x86)\Microsoft SQL Server" /INSTANCEID="MSSQLSERVER" /INSTANCEDIR="C:\Program Files\Microsoft SQL Server" /AGTSVCACCOUNT="{0}" /AGTSVCPASSWORD="{1}" /FILESTREAMLEVEL="0" /SQLSVCACCOUNT="{0}" /SQLSVCPASSWORD="{1}" /SQLSVCINSTANTFILEINIT="False" /FTSVCACCOUNT="NT Service\MSSQLFDLauncher"' -f $SqlUserName, $SqlUserPassword
Invoke-Command -scriptblock {
    Start-Process -FilePath C:\SQLinstallmedia\setup.exe -ArgumentList $Using:arguments -Wait -NoNewWindow
} -Credential $Credentials -ComputerName $HostAddress -Authentication credssp
