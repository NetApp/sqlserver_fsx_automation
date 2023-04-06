[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$DomainNetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$AdminSecret,

    [Parameter(Mandatory=$true)]
    [string]$FSxSVMIscsiIP1,

    [Parameter(Mandatory=$true)]
    [string]$FSxSVMIscsiIP2,

    [Parameter(Mandatory=$true)]
    [string]$SqlFSxInstanceIP,

    [Parameter(Mandatory=$true)]
    [string]$LUNSize

)

$HostName = hostname

# Getting Password from Secrets Manager for AD Admin User
$AdminUser = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $AdminSecret).SecretString
$ClusterAdminUser = $DomainNetBIOSName + '\' + $AdminUser.UserName
# Creating Credential Object for Administrator
$Credentials = (New-Object PSCredential($ClusterAdminUser,(ConvertTo-SecureString $AdminUser.Password -AsPlainText -Force)))


Invoke-Command -ScriptBlock {
    # need to fix this part
    $TargetPortals = ("$Using:FSxSVMIscsiIP1","$Using:FSxSVMIscsiIP2")
    foreach ($TargetPortal in $TargetPortals) {New-IscsiTargetPortal -TargetPortalAddress $TargetPortal -TargetPortalPortNumber 3260 -InitiatorPortalAddress $Using:SqlFSxInstanceIP}
    New-MSDSMSupportedHW -VendorId MSFT2005 -ProductId iSCSIBusType_0x9
    1..4 | %{Foreach($TargetPortal in $TargetPortals){Get-IscsiTarget | Connect-IscsiTarget -IsMultipathEnabled $true -TargetPortalAddress $TargetPortal -InitiatorPortalAddress $Using:SqlFSxInstanceIP -IsPersistent $true} }
    Set-MSDSMGlobalDefaultLoadBalancePolicy -Policy RR
    $disks = Get-Disk | where PartitionStyle -eq raw
    foreach ($disk in $disks) {Initialize-Disk $disk.Number}
    $diskNumberString = Get-Disk | findstr NETAPP | findstr Online | findstr $Using:LUNSize
    $diskNumber = $diskNumberString.split()[0]
    New-Partition -DiskNumber $diskNumber -DriveLetter G -UseMaximumSize
    Format-Volume -DriveLetter G -FileSystem NTFS -AllocationUnitSize 65536

} -Credential $Credentials -ComputerName $HostName -Authentication credssp