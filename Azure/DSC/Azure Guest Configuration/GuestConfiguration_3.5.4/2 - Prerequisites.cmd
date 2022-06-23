robocopy /mir "\\tsclient\C\laurentvanacker.com\Azure\DSC\Azure Guest Configuration" "C:\Azure Guest Configuration"
cd "C:\Azure Guest Configuration\GuestConfiguration_3.5.4"
PowerShell -File "C:\Azure Guest Configuration\GuestConfiguration_3.5.4\2 - Prerequisites.ps1" -ExecutionPolicy ByPass
start powershell_ise "C:\Azure Guest Configuration\GuestConfiguration_3.5.4\2 - Prerequisites.ps1"

