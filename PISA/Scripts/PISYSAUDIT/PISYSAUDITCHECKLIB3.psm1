# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB3.psm1
# * Version:      1.0.0.8
# * Description:  Validation rules for PI AF Server.
# * Authors:  Jim Davidson, Bryan Owen and Mathieu Hamel from OSIsoft.
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
function Get-PISysAudit_FunctionsFromLibrary3
{
	# Form a list of all functions that need to be called to test
	# the PI AF Server compliance.
	[System.Collections.HashTable]$listOfFunctions = @{}	
	$listOfFunctions.Add("Get-PISysAudit_CheckPIAFServiceConfiguredAccount", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPImpersonationModeForAFDataSets", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPIAFServicePrivileges", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPlugInVerifyLevel", 1)	
	$listOfFunctions.Add("Get-PISysAudit_CheckFileExtensionWhitelist", 1)		
	
	# Return the list.
	return $listOfFunctions
}

function Get-PISysAudit_CheckPIAFServiceConfiguredAccount
{
<#  
.SYNOPSIS
AU30001 - PI AF Server Service Account Check
.DESCRIPTION
Audit ID: AU30001
Audit Check Name: PI AF Server Service Account Check
Category: Severe
Compliance: Should not be executed with LocalSystem, all other accounts
are considered good.
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
		# Get the service account.
		$value = Get-PISysAudit_ServiceLogOnAccount "afservice" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel				
		
		# Check if the value is <> LocalSystem		
		if($value.ToLower() -eq "localsystem") { $result =  $false } else { $result = $true }				
	}
	catch
	{ $result = "N/A" }
	
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30001" `
										-ain "Configured Account Check" -aiv $result `
										-Group1 "PI AF Server" `
										-Severity "Severe"
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPImpersonationModeForAFDataSets
{
<#  
.SYNOPSIS
AU30002 - Impersonation mode for AF Data Sets Check
.DESCRIPTION
Audit ID: AU30002
Audit Check Name: Impersonation mode for AF Data Sets
Category: Low
Compliance: Should be false.
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
		# Invoke the afdiag.exe command.		
		$outputFileContent = Invoke-PISysAudit_AFDiagCommand -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
	
		#.................................
		# Validate rules
		# (Do not remove)
		#.................................
		# Example of output.
		# SQL Connection String: 'Persist Security Info=False;Integrated
		# Security=SSPI;server=PISYSTEM2;database=PIFD;Application Name=AF
		# Application Server;'

		# System Name = PISYSTEM2
		# SystemID = 6a5c9048-38c7-40fb-a65f-bcaf729580c5
		# Database Settings:
		# ...
		# Configuration Settings:
		# 	Audit Trail = Disabled
		# 	EnableExternalDataTables = True
		# 	ExternalDataTablesAllowNonImpersonatedUsers = False
		# 	EnableExternalDataTablesWithAF20 = False
		# 	EnableSandbox = True
		# 	EnablePropagateElementDeletesToAnalysisandNotification = True
		# 	EnableEventFrames = True
		
		# Read each line to find the one containing the token to replace.
		# Check if the value is false = compliant, true it is not compliant
		$result = $true
		foreach($line in $outputFileContent)
		{								
			if($line.Contains("ExternalDataTablesAllowNonImpersonatedUsers"))
			{								
				if($line.Contains("True")) { $result = $false }
				break
			}						
		}				
	}
	catch
	{ $result = "N/A" }	
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30002" `
										-ain "Impersonation mode for AF Data Sets" -aiv $result `
										-Group1 "PI AF Server" `
										-Severity "Low"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPIAFServicePrivileges
{
<#  
.SYNOPSIS
AU30003 - PI AF Server Service Access Check
.DESCRIPTION
Audit ID: AU30003
Audit Check Name: PI AF Server Service Access Check
Category: Severe
Compliance: Should not contain SeDebugPrivilege, SeTakeOwnershipPrivilege, SeTcbPrivilege privileges to
considered good.
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
		# Initialize objects.
		$securityWeaknessCounter = 0	
		$securityWeakness = $false
		$privilegeFound = $false		
		$warningMessage = ""
		
		# Get the service account.
		$listOfPrivileges = Get-PISysAudit_CheckPrivilege -lc $LocalComputer -rcn $RemoteComputerName -pv "All" -sn "AFService" -dbgl $DBGLevel					
		
		# Read each line to find granted privileges.		
		foreach($line in $listOfPrivileges)
		{											
			# Reset.
			$securityWeakness = $false						
			$privilegeFound = $false			
			
			# Skip any line not starting with 'SE'
			if($line.ToUpper().StartsWith("SE")) 
			{								
				# Validate that the tokens contains these privileges.
				if($line.ToUpper().Contains("SEDEBUGPRIVILEGE")) { $privilegeFound = $true }
				if($line.ToUpper().Contains("SETAKEOWNERSHIPPRIVILEGE")) { $privilegeFound = $true }
				if($line.ToUpper().Contains("SETCBPRIVILEGE")) { $privilegeFound = $true }
				
				# Validate that the privilege is enabled, if yes a weakness was found.
				if($privilegeFound -and ($line.ToUpper().Contains("ENABLED"))) { $securityWeakness = $true }
			}							

			# Increment the counter if a weakness has been discovered.
			if($securityWeakness)
			{
				$securityWeaknessCounter++
				
				# Store the privilege found that might compromise security.
				if($securityWeaknessCounter -eq 1)
				{ $warningMessage = $line.ToUpper() }
				else
				{ $warningMessage = $warningMessage + ", " + $line.ToUpper() }
			}					
		}
		
		# Check if the counter is 0 = compliant, 1 or more it is not compliant		
		if($securityWeaknessCounter -gt 0)
		{
			$result = $false
			if($securityWeaknessCounter -eq 1)
			{ $warningMessage = "The following privilege: " + $warningMessage + " is enabled." }
			else
			{ $warningMessage = "The following privileges: " + $warningMessage + " are enabled." }
		}
		else { $result = $true }
	}
	catch
	{ $result = "N/A" }
	
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30003" `
										-ain "PI AF Server Service privileges" -aiv $result `
										-msg $warningMessage `
										-Group1 "PI AF Server" `
										-Severity "Severe"																					
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPlugInVerifyLevel
{
<#  
.SYNOPSIS
AU30004 - PI AF Server Plugin Verify Level Check
.DESCRIPTION
Audit ID: AU30004
Audit Check Name: PI AF Server Plugin Verify Level Check
Category: Moderate
Compliance: Should be either RequireSigned or RequireSignedTrustedProvider.
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
		# Invoke the afdiag.exe command.		
		$outputFileContent = Invoke-PISysAudit_AFDiagCommand -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
		
		# Read each line to find the one containing the token to replace.
		# Check if the value is false = compliant, true it is not compliant
		$result = $true
		foreach($line in $outputFileContent)
		{								
			if($line.Contains("PlugInVerifyLevel"))
			{								
				if($line.Contains("AllowUnsigned") -or $line.Contains("None")) { $result = $false }
				break
			}						
		}				
	}
	catch
	{ $result = "N/A" }	
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30004" `
										-ain "PI AF Server Plugin Verify Level Check" -aiv $result `
										-Group1 "PI AF Server" `
										-Severity "Moderate"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckFileExtensionWhitelist
{
<#  
.SYNOPSIS
AU30005 - PI AF Server File Extension Whitelist
.DESCRIPTION
Audit ID: AU30005
Audit Check Name: PI AF Server File Extension Whitelist
Category: Moderate
Compliance: Should only include the file extensions: docx:xlsx:csv:pdf:txt:rtf:jpg:jpeg:png:svg:tiff:gif or a subset thereof.
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
		# Invoke the afdiag.exe command.		
		$outputFileContent = Invoke-PISysAudit_AFDiagCommand -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
		
		# Read each line to find the one containing the token to replace.
		# Check if the value is false = compliant, true it is not compliant
		$result = $true
		foreach($line in $outputFileContent)
		{								
			# Locate FileExtensions parameter
			if($line.Contains("FileExtensions"))
			{								
				# Master whitelist of approved extensions
				[System.Collections.ArrayList] $allowedExtensions = 'docx','xlsx','csv','pdf','txt','rtf','jpg','jpeg','png','svg','tiff','gif'
				# Extract configured whitelist from parameter value
				[string] $extensionList = $line.Split('=')[1].TrimStart()
				[string[]] $extensions = $extensionList.Split(':')
				# Loop through the configured extensions
				foreach($extension in $extensions) 
				{ 
					# Assume extension is a violation until proven compliant
					$result = $false
					# As soon as the extension is found in the master list, we move to the next one
					foreach($allowedExtension in $allowedExtensions)
					{
						if($extension -eq $allowedExtension) 
						{ 
							$result = $true
							# There should not be duplicates so we don't need include that extension in further iterations
							$allowedExtensions.Remove($extension)
							break
						}
						else {$result = $false}
					}
					# If we detect any rogue extension, the validation check fails, no need to look further
					if($result -eq $false) {break}
				} 
				break
			}						
		}				
	}
	catch
	{ $result = "N/A" }	
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30005" `
										-ain "PI AF Server File Extension Whitelist" -aiv $result `
										-Group1 "PI AF Server" `
										-Severity "Moderate"
										
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
function Get-PISysAudit_TemplateAU3xxxx
{
<#  
.SYNOPSIS
AU3xxxx - <Name>
.DESCRIPTION
Audit ID: AU3xxxx
Audit Check Name: <Name>
Category: <Category>
Compliance: <Enter what it needs to be compliant>
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
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary3
Export-ModuleMember Get-PISysAudit_CheckPIAFServiceConfiguredAccount
Export-ModuleMember Get-PISysAudit_CheckPImpersonationModeForAFDataSets
Export-ModuleMember Get-PISysAudit_CheckPIAFServicePrivileges
Export-ModuleMember Get-PISysAudit_CheckPlugInVerifyLevel
Export-ModuleMember Get-PISysAudit_CheckFileExtensionWhitelist
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU3xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU3xxxx