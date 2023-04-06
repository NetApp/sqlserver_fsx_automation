[CmdletBinding()]

Write-Output "Iscsi Setup started"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Start-service -Name msiscsi
Set-Service -Name msiscsi -StartupType Automatic
Write-Output "Iscsi Setup completed"