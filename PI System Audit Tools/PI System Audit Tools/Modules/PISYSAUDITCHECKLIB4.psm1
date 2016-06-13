# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB4.psm1
# * Version:      1.0.0.8
# * Description:  Validation rules for SQL Server.
# * Authors:  Jim Davidson, Bryan Owen and Mathieu Hamel from OSIsoft.
# * Structure:
#
# * DISCLAIMER: This sample code is provided to members of the 
# * OSIsoft Users Community (http://community.osisoft.com) 
# * and is subject to the OSIsoft Users Community End-User License Agreement,
# * found at ...
# * 
# * All sample code is provided by OSIsoft for illustrative purposes only.
# * These examples have not been thoroughly tested under all conditions.
# * OSIsoft provides no guarantee nor implies any reliability, 
# * serviceability, or function of these programs.
# * ALL PROGRAMS CONTAINED HEREIN ARE PROVIDED TO YOU "AS IS" 
# * WITHOUT ANY WARRANTIES OF ANY KIND. ALL WARRANTIES INCLUDING 
# * THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY
# * AND FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY DISCLAIMED.
# ************************************************************************
# Version History:
# ------------------------------------------------------------------------
# Version 1.0.0.8 Initial release on OSIsoft Users Community.
#
# ************************************************************************

# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

# ........................................................................
# Public Functions
# ........................................................................
function Get-PISysAudit_FunctionsFromLibrary4
{
	# Form a list of all functions that need to be called to test
	# the SQL Server compliance.
	[System.Collections.HashTable]$listOfFunctions = @{}	
	$listOfFunctions.Add("Get-PISysAudit_CheckSQLXPCommandShell", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckSQLAdHocQueries", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckSQLDBMailXPs", 1)			
	$listOfFunctions.Add("Get-PISysAudit_CheckSQLOLEAutomationProcs", 1)			
	
	# Return the list.
	return $listOfFunctions		
}

function Get-PISysAudit_CheckSQLXPCommandShell
{
<#  
.SYNOPSIS
AU40001 - SQL Server xp_CmdShell Check
.DESCRIPTION
Audit ID: AU40001
Audit Check Name: SQL Server xp_CmdShell Check
Category: Severe
Compliance: Must not be enabled.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{	
	# Get and store the function Name.
	$fn = GetFunctionName	
	
	try
	{											
		# Build and execute the query.			
		$query = "SELECT value_in_use FROM Master.sys.configurations WHERE name = 'xp_cmdshell'"		
		$value = Invoke-PISysAudit_SQLCMD_ScalarValueFromSQLServerQuery -lc $LocalComputer -rcn $RemoteComputerName `
																		-q $query -rspc $true -InstanceName $InstanceName `
																		-IntegratedSecurity $IntegratedSecurity `
																		-user $UserName -pf $PasswordFile `
																		-dbgl $DBGLevel	
								
		# Check if the value is 1 = not compliant, 0 it is.								
		if($value -eq $null)
		{
			# Return the error message.
			$msg = "A problem occured during the processing of SQL Server Server checks (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
			$result = "N/A"
		}				
		elseif($value -eq 0) { $result = $true }
		else { $result = $true }	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occured during the processing of SQL Server Server checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
				
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU40001" `
										-ain "SQL Server xp_CmdShell Check" -aiv $result `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "Severe"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLAdHocQueries
{
<#  
.SYNOPSIS
AU40002 - SQL Server Adhoc Queries Check
.DESCRIPTION
Audit ID: AU40002
Audit Check Name: SQL Server Adhoc Queries
Category: Severe
Compliance: Must not be enabled.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{	
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{											
		# Build and execute the query.			
		$query = "SELECT value_in_use FROM Master.sys.configurations WHERE name = 'Ad Hoc Distributed Queries'"				
		$value = Invoke-PISysAudit_SQLCMD_ScalarValueFromSQLServerQuery -lc $LocalComputer -rcn $RemoteComputerName `
																		-q $query -rspc $true -InstanceName $InstanceName `
																		-IntegratedSecurity $IntegratedSecurity `
																		-user $UserName -pf $PasswordFile `
																		-dbgl $DBGLevel	
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($value -eq $null)
		{
			# Return the error message.
			$msg = "A problem occured during the processing of SQL Server Server checks (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
			$result = "N/A"
		}				
		elseif($value -eq 0) { $result = $true }
		else { $result = $true }	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occured during the processing of SQL Server Server checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
				
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU40002" `
										-ain "SQL Server Adhoc Queries Check" -aiv $result `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "Severe"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLDBMailXPs
{
<#  
.SYNOPSIS
AU40003 - SQL Server DB Mail XPs Check
.DESCRIPTION
Audit ID: AU40003
Audit Check Name: SQL Server DB Mail XPs
Category: Severe
Compliance: Must not be enabled.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{	
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{											
		# Build and execute the query.			
		$query = "SELECT value_in_use FROM Master.sys.configurations WHERE name = 'Database Mail XPs'"				
		$value = Invoke-PISysAudit_SQLCMD_ScalarValueFromSQLServerQuery -lc $LocalComputer -rcn $RemoteComputerName `
																		-q $query -rspc $true -InstanceName $InstanceName `
																		-IntegratedSecurity $IntegratedSecurity `
																		-user $UserName -pf $PasswordFile `
																		-dbgl $DBGLevel	
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($value -eq $null)
		{
			# Return the error message.
			$msg = "A problem occured during the processing of SQL Server Server checks (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
			$result = "N/A"
		}				
		elseif($value -eq 0) { $result = $true }
		else { $result = $true }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occured during the processing of SQL Server Server checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
				
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU40003" `
										-ain "SQL Server DB Mail XPs Check" -aiv $result `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "Severe"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLOLEAutomationProcs
{
<#  
.SYNOPSIS
AU40004 - SQL Server OLE Automation Procedures Check
.DESCRIPTION
Audit ID: AU40004
Audit Check Name: SQL Server OLE Automation Procedures
Category: Severe
Compliance: Must not be enabled.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{	
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{											
		# Build and execute the query.			
		$query = "SELECT value_in_use FROM Master.sys.configurations WHERE name = 'Ole Automation Procedures'"				
		$value = Invoke-PISysAudit_SQLCMD_ScalarValueFromSQLServerQuery -lc $LocalComputer -rcn $RemoteComputerName `
																		-q $query -rspc $true -InstanceName $InstanceName `
																		-IntegratedSecurity $IntegratedSecurity `
																		-user $UserName -pf $PasswordFile `
																		-dbgl $DBGLevel	
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($value -eq $null)
		{
			# Return the error message.
			$msg = "A problem occured during the processing of SQL Server Server checks (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
			$result = "N/A"
		}				
		elseif($value -eq 0) { $result = $true }
		else { $result = $true }	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occured during the processing of SQL Server Server checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
				
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU40004" `
										-ain "SQL Server OLE Automation Procedures Check" -aiv $result `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "Severe"
										
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Add your cmdlet after this section. Don't forget to add an intruction
# to export them at the bottom of this script.
# ........................................................................
function Get-PISysAudit_TemplateAU4xxxx
{
<#  
.SYNOPSIS
AU4xxxx - <Name>
.DESCRIPTION
Audit ID: AU4xxxx
Audit Check Name: <Name>
Category: <Category>
Compliance: <Enter what it needs to be compliant>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at,AT")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{	
	# Get and store the function Name.
	$fn = GetFunctionName

try
	{		
		# Enter routine.			
	}
	catch
	{ $result = "N/A" }	
			
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU3xxxx" `
										-ain "<Name>" -aiv $result `
										-msg "<Message>" `
										-Group1 "<Category 1>" -Group2 "<Category 2>" -Group3 "<Category 3>" -Group4 "<Category 4>"`
										-Severity "<Severity>"
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Export Module Member
# ........................................................................
# <Do not remove>
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary4
Export-ModuleMember Get-PISysAudit_CheckSQLXPCommandShell
Export-ModuleMember Get-PISysAudit_CheckSQLAdHocQueries
Export-ModuleMember Get-PISysAudit_CheckSQLDBMailXPs
Export-ModuleMember Get-PISysAudit_CheckSQLOLEAutomationProcs
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU4xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU4xxxx