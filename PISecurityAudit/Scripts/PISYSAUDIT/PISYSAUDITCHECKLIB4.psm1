# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB4.psm1
# * Version:      1.0.0.8
# * Description:  Validation rules for SQL Server.
# * Authors:  Jim Davidson, Bryan Owen and Mathieu Hamel from OSIsoft.
# * Structure:
# *
# * Copyright 2016 OSIsoft, LLC
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# * 
# *   <http://www.apache.org/licenses/LICENSE-2.0>
# * 
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *
# * Modifications copyright (C) <YYYY> <Name>, <Org>
# * <Description of modification>
# *
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
VALIDATION: verifies that SQL Server does not have xp_CmdShell enabled.<br/>
COMPLIANCE: disable xp_CmdShell configuration option.  This option can be configured 
using the Policy-Based Management or the sp_configure stored procedure.  For more 
information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms190693.aspx">https://msdn.microsoft.com/en-us/library/ms190693.aspx</a>
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
	$msg = ""
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
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{ 
			$result = $true 
			$msg = "xp_cmdshell disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "xp_cmdshell enabled." 
		}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
				
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU40001" `
										-msg $msg `
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
VALIDATION: verifies that SQL Server does not have Ad Hoc Distributed Queries enabled.<br/>    
COMPLIANCE: disable Ad Hoc Distributed Queries configuration option.  This option can be 
configured using the Policy-Based Management or the sp_configure stored procedure. For more 
information, see:<br/> 
<a href="https://msdn.microsoft.com/en-us/library/ms187569.aspx">https://msdn.microsoft.com/en-us/library/ms187569.aspx </a>
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
	$msg = ""
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
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{ 
			$result = $true 
			$msg = "Ad Hoc Distributed Queries disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Ad Hoc Distributed Queries enabled."
		}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
				
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU40002" `
										-msg $msg `
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
VALIDATION CHECK: verifies that SQL Server does not have Ad Hoc Distributed Queries enabled.</br>
FOR COMPLIANCE: disable Database Mail XPs configuration option.  This option can be configured 
using the Policy-Based Management or the sp_configure stored procedure. For more information, 
see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms191189.aspx">https://msdn.microsoft.com/en-us/library/ms191189.aspx</a>
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
	$msg = ""
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
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{ 
			$result = $true 
			$msg = "Database Mail XPs disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Database Mail XPs enabled."
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
				
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU40003" `
										-msg $msg `
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
VALIDATION: verifies that SQL Server does not have OLE Automation Procedures enabled.<br/> 
COMPLIANCE: disable the OLE Automation Procedures configuration option.  This option can 
be configured using the Policy-Based Management or the sp_configure stored procedure. For 
more information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms191188.aspx">https://msdn.microsoft.com/en-us/library/ms191188.aspx</a>
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
	$msg = ""
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
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{
			$result = $true 
			$msg = "Ole Automation Procedures disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Ole Automation Procedures enabled."
		}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
				
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU40004" `
										-ain "SQL Server OLE Automation Procedures Check" -aiv $result `
										-msg $msg `
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
VERIFICATION: <Enter what the verification checks>
COMPLIANCE: <Enter what it needs to be compliant>
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
	$msg = ""
try
	{		
		# Enter routine.			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
			
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU3xxxx" `
										-ain "<Name>" -aiv $result `
										-msg $msg `
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