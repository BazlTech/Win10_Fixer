# Windows 10 Fixer Script

Thisc script automates bloatware removal, ssl hardening, telemetry/tracking removal, and more.

| ❗ Use this script at your own risk.  Scripts from unknown sources should be reviewed before execution |
|----------------------------------------------------------------------------------------------------------------------|

## Usage

You'll need to run the following for each PowerShell session in order to enable the script to run
```powershell
Set-ExecutionPolicy RemoteSigned –Scope Process
```

The script will prompt if you want it to run each module:
- RemoveWinBloat
  - You should first edit the array variable to add or remove packages to be removed
- RemoveXboxBloat
- RemoveOneDrive
- RemoveCortana
- Remove_NewsInterests
- Harden_SSL
  - Includes implementing TLSv1.3 and setting secure cipher suite order
- ClearDefaultStartMenu
  - Only affects users added after script is run

You'll need to restart your computer when you are finished.

For more details, see: https://bazl.tech/p/windows-10-fixer-script-cleanup-windows-with-powershell/
