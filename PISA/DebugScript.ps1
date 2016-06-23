#
# DebugScript.ps1
#

If(Get-Module PISYSAudit){
Remove-Module PISYSAudit}
Import-Module C:\Users\asorokina\Source\Repos\PI-System-Audit-Tools\PISA\PISYSAUDIT.psd1
piaudit