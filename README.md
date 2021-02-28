# PowerShell-Enum-Script
An practice enumeration script checking for basic information taken from the Windows Registry and using Windows APIs.

It retrieves from the host:
- The hostname
- The OS, architecture and version, including installed hotfixes
- A list of installed programs
- Local user accounts
- Proxy information
- Saved PuTTy Sessions
- Recent PuTTY Sessions
- Putty SSH Keys
- The directory of stored SSH Keys

To use:

1. Check your execution policy of powershell scripts with the PowerShell command:
```
Get-ExecutionPolicy
```
If it returns: **Restricted**, **AllSigned** or **RemoteSigned** you will have to change the execution policy to allow this script to be run.

2. To set the execution policy of powershell scripts use the PowerShell command:

```
Set-ExecutionPolicy Unrestricted
```
3. You are now ready to execute the enumeration script by using the following command in the Windows Command Prompt in the same directory that you have placed the script:
```
powershell .\Windows-Enumeration-Script.ps1
```
4. Remember to re-enable the execution policy as this can be risky. You can do this by issuing the PowerShell Command:
```
Set-ExecutionPolicy Restricted
```
