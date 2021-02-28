<#
A windows enumeration program.

Author: Oliver Muscatello
Date: 23 January 2021
#>
function Main {
# Get the hosts' host name
  Get-Hostname

# Get the operating system information on this host
  Get-OSInfo

# List all of the programs installed on this host
  Get-Progs

# Get all local users of this host
  Get-Users

# Get Win 10 Proxy information
  Get-ProxyInfo

# Get all stored PuTTy session information
  Get-PuttySessions

# Get recent PuTTy sessions
  get-RecentPuttySessions

# Get the private key for a puTTy public key auth session
  Get-PuttyKeysReg

# Check for stored SSH keys in users home directory
  Get-SSHKeys

# Get stored RDP session information
  get-PastRDP

# Get the past 100 most recent commands used in this terminal session
  get-CmdHistory
}
<#
This function formats the title of the enumerated information
#>
function String-Format([String] $title) {
    Write-Host `n
    Write-Host -ForegroundColor Green -NoNewline "Getting "
    Write-Host -ForegroundColor Green -NoNewline $title
    Write-Host -ForegroundColor Green ":"
}
<#
This function formats all errors with the title of the function that caused it
#>
function String-Error([String] $title) {
    Write-Host `n
    Write-Host -ForegroundColor Red -NoNewline "Unable to retrieve any "
    Write-Host -ForegroundColor Red $title
}
<#
Gets and prints the hostname of the device
#>
function Get-Hostname {
  $title = "Hostname"
  $hn = $env:computername
  String-Format($title)
  return $hn
}
<#
Gets and prints the Operating System, the CPU Architecture and the Version among other information
#>
function Get-OSInfo {
  $title = "OS, Architecture and Version"
  $osinfo = systeminfo /fo csv | ConvertFrom-Csv | select OS*, System*, Hotfix* | Format-List
  String-Format($title)
  return $osinfo
}
<#
Gets and prints Windows local accounts
#>
function Get-Users {
  $title = "Users"
  String-Format($title)
  $users = Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'"
  foreach ($user in $users) {
    Write-Host $user
    Write-Host `n
  }
}
<#
Gets and prints installed programs on the host
#>
function Get-Progs {
  $title = "Installed Programs"
  String-Format($title)
  $reg = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  if(![string]::IsNullOrEmpty($reg)) {
    $names = $reg | foreach-object {Get-ItemProperty $_.PsPath}
    foreach ($name in $names)
    {
      if(-Not [string]::IsNullOrEmpty($name.DisplayName)) {
        $line = $name.DisplayName
        Write-Host $line
      }
    }
} else {
    String-Error($title)
  }
}
<#
Gets and prints proxy information on Win 10 from the Windows registry
#>
function Get-ProxyInfo {
  $title = "Proxy Info"
  String-Format($title)
  $ProxyInfo = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object "Proxy*"
  Write-Host $ProxyInfo
}
<#
Gets and prints saved PuTTy sessions from the Windows registry
#>
function get-PuttySessions {
  $title = "Saved PuTTY Sessions"
  String-Format($title)
  $sessions = Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions"
  $properties = @('HostName','Protocol','PortNumber','PublicKeyFile', 'HostKey')

  if(![string]::IsNullOrEmpty($sessions)) {
    foreach ($session in $sessions) {
      Foreach ($property in $properties) {
          Write-Host -NoNewLine $property": "
          Write-Host $session.GetValue($property)
          }
    }
} else {
    String-Error($title)
  }
}
<#
Gets and prints recent PuTTy sessions from the Windows registry
#>
function get-RecentPuttySessions {
  $title = "Recent PuTTy Sessions"
  String-Format($title)
  $sessions = Get-Item "HKCU:\Software\SimonTatham\PuTTY\Jumplist"
  $properties = @('Recent sessions')
  if(![string]::IsNullOrEmpty($sessions)) {
    foreach ($session in $sessions) {
        Foreach ($property in $properties) {
            Write-Host -NoNewLine $property": "
            Write-Host $session.GetValue($property)
        }
    }
} else {
    String-Error($title)
  }
}
<#
Gets and prints PuTTy SSH host keys from the Windows registry
#>
function get-PuttyKeysReg {
  $title = "Putty SSH Keys"
  String-Format($title)
  $sshKeys = Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys" | Select-Object "*ssh*"
  if(![string]::IsNullOrEmpty($sshKeys)){
    Write-Host $sshKeys
} else {
    String-Error($title)
  }
}
<#
Checks for and prints the contents of the .ssh folder under a users home directory
#>
function get-SSHKeys {
  $title = "Location of Stored SSH Keys"
  String-Format($title)
  $storedKeys = Get-ChildItem C:\Users\*\.ssh\*
  if(![string]::IsNullOrEmpty($storedKeys)){
    foreach($storedKey in $storedKeys){
      Write-Host $storedKey
      Write-Host `n
    }
} else {
    String-Error($title)
  }
}
<#
Gets and prints RDP sessions from the Windows registry
#>
function get-PastRDP {
  $title = "Past RDP Sessions"
  String-Format($title)
  $sessions = Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
  $properties = @($sessions, 'UsernameHint')

  if(![string]::IsNullOrEmpty($sessions)) {
    foreach ($session in $sessions) {
      Foreach ($property in $properties) {
          Write-Host -NoNewLine $property": "
          Write-Host $session.GetValue($property)
          }
    }
} else {
    String-Error($title)
  }
}
<#
Gets and prints the last 100 commands used in the terminal session
#>
function get-CmdHistory {
  $title = "Last 100 Commands Run"
  String-Format($title)
  $cmdHistory = Get-History -Count 100
  Write-Host $cmdHistory
}
Main
