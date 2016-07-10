#
# DebugScript.ps1
#

If(Get-Module PISYSAudit){
Remove-Module PISYSAudit}
$modulepath = $PSScriptRoot + '.\PISYSAUDIT.psd1'
Import-Module $modulepath
piaudit