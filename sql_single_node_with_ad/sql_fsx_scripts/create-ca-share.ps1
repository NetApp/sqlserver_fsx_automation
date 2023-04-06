[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$DomainNetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$AdminSecret,

    [Parameter(Mandatory=$false)]
    [string]$FSxRemoteAdminEndpoint

)


$AdminUser = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $AdminSecret).SecretString
$ClusterAdminUser = "fsxadmin"
# Creating Credential Object for Administrator
$Credentials = (New-Object PSCredential($ClusterAdminUser,(ConvertTo-SecureString "NetApp123" -AsPlainText -Force)))

#Configure CA SMB share on FSx
#vserver cifs share create -vserver vs1 -share-name SALES_SHARE -path /sales -symlink-properties enable
$shareName = "SqlShare"
Invoke-Command -ComputerName $FSxRemoteAdminEndpoint -scriptblock {
  vserver cifs share create -vserver SqlFSxSVM -share-name $Using:shareName -path /vol1 -symlink-properties enable
} -Credential $Credentials

#Configure Witness SMB share on FSx
$WitnessshareName = "SqlWitnessShare"
Invoke-Command -ComputerName $FSxRemoteAdminEndpoint -scriptblock {
  vserver cifs share create -vserver SqlFSxSVM -share-name $Using:WitnessshareName -path /vol1 -symlink-properties enable
} -Credential $Credentials
