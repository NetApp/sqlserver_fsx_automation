[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$FSxSVMIscsiIP1,

    [Parameter(Mandatory=$true)]
    [string]$FSxSVMIscsiIP2,

    [Parameter(Mandatory=$true)]
    [string]$SqlFSxInstanceIP,

    [Parameter(Mandatory=$true)]
    [string]$LUNSize

)


$TargetPortals = ("$FSxSVMIscsiIP1","$FSxSVMIscsiIP2")
foreach ($TargetPortal in $TargetPortals) {New-IscsiTargetPortal -TargetPortalAddress $TargetPortal -TargetPortalPortNumber 3260 -InitiatorPortalAddress $SqlFSxInstanceIP}
New-MSDSMSupportedHW -VendorId MSFT2005 -ProductId iSCSIBusType_0x9
1..4 | %{Foreach($TargetPortal in $TargetPortals){Get-IscsiTarget | Connect-IscsiTarget -IsMultipathEnabled $true -TargetPortalAddress $TargetPortal -InitiatorPortalAddress $SqlFSxInstanceIP -IsPersistent $true} }
Set-MSDSMGlobalDefaultLoadBalancePolicy -Policy RR
$disks = Get-Disk | where PartitionStyle -eq raw
foreach ($disk in $disks) {Initialize-Disk $disk.Number}
$diskNumberString = Get-Disk | findstr NETAPP | findstr Online | findstr $LUNSize
$diskNumber = $diskNumberString.split()[0]
New-Partition -DiskNumber $diskNumber -DriveLetter G -UseMaximumSize
Format-Volume -DriveLetter G -FileSystem NTFS -AllocationUnitSize 65536