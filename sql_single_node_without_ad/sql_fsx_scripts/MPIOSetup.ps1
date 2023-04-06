[CmdletBinding()]

winrm quickconfig -quiet
Install-WindowsFeature -name Multipath-IO -Restart
