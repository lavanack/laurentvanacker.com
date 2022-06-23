robocopy /mir "\\tsclient\C\laurentvanacker.com\Azure\DSC\Azure Guest Configuration" "C:\Azure Guest Configuration"
cd "C:\Azure Guest Configuration\GuestConfiguration_4.1.0"
PowerShell -File "C:\Azure Guest Configuration\GuestConfiguration_4.1.0\2 - Prerequisites.ps1" -ExecutionPolicy ByPass
start powershell_ise "C:\Azure Guest Configuration\GuestConfiguration_4.1.0\2 - Prerequisites.ps1"

