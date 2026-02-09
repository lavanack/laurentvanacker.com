<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment. THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>

#region Set the French as Display Language for Office for all users via Local Machine Policies in the Registry (HKLM)
$LangId = 'fr-fr'
$Policies = 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\LanguageResources'
New-Item -Path $Policies -Force
New-ItemProperty -Path $Policies -Name 'InstallLanguage' -Value 0x040C -PropertyType DWord -Force
New-ItemProperty -Path $Policies -Name 'UILanguage' -Value $LangId -PropertyType String -Force
New-ItemProperty -Path $Policies -Name 'PreferredEditingLanguage' -Value $LangId -PropertyType String -Force
New-ItemProperty -Path $Policies -Name 'HelpLanguage' -Value $LangId -PropertyType String -Force
#endregion