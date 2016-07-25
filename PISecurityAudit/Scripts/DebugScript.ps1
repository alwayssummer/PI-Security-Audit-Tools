#
# DebugScript.ps1
#

If(Get-Module PISYSAudit){
Remove-Module PISYSAudit}
$modulepath = (Split-Path $PSScriptRoot) + '\PISYSAUDIT.psd1'
Import-Module $modulepath
piaudit 