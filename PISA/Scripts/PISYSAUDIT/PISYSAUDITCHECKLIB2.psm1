# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB2.psm1
# * Version:      1.0.0.8
# * Description:  Validation rules for PI Data Archive.
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
function Get-PISysAudit_FunctionsFromLibrary2
{
	# Form a list of all functions that need to be called to test
	# the PI Server compliance.
	[System.Collections.HashTable]$listOfFunctions = @{}	
	$listOfFunctions.Add("Get-PISysAudit_CheckPIServerDBSecurity_PIWorldReadAccess", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPIServerSubSysVersions", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPIAdminTrustsDisabled", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckEditDays", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckAutoTrustConfig", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckExpensiveQueryProtection", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckExplicitLoginDisabled",1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPIAdminUsage",1)
			
	# Return the list.
	return $listOfFunctions	
}

function Get-PISysAudit_CheckPIServerDBSecurity_PIWorldReadAccess
{
<#  
.SYNOPSIS
AU20001 - PI Data Archive Table Security Check
.DESCRIPTION
Audit ID: AU20001
Audit Check Name: PI Data Archive Table Security
Category: Moderate
Compliance: Should be part of a domain.
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
		$warningMessage = ""
														
		# Execute the PIConfig script.
		$outputFileContent = Invoke-PISysAudit_PIConfigScript -f "CheckPIWorldReadAccess.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel				
		
		# Validate rules	
	
		# Example of output.
		# PIAFLINK^piadmin: A(r,w) | piadmins: A(r,w) | PIWorld: A()
		# PIARCADMIN^piadmin: A(r,w) | piadmins: A(r,w) | PIWorld: A()
		# PIARCDATA^piadmin: A(r,w) | piadmins: A(r,w) | PIWorld: A()
		# ...

		# Read each line to find the one containing the token to replace.		
		foreach($line in $outputFileContent)
		{								
			# Skip line if not containing the delimiter.
			if($line.Contains("^"))
			{             		
                # Find the delimiter
				$position = $line.IndexOf("^")			
				
				# Specific Database
				$length  = $position
				$dbName = $line.SubString(0, $length)
				
				# Find the ACL
				$length  = $line.Length - $position - 1
				$acl = ($line.SubString($position + 1, $length)).ToLower()
				
                $process = $false
                # Perform the test on specific databases.
                Switch($dbName.ToLower())
                {
                    "pibatch" { $process = $true }
                    "pibatchlegacy" { $process = $true }
                    "picampaign" { $process = $true }
                    "pidbsec" { $process = $true }
                    "pids" { $process = $true }
                    "piheadingsets" { $process = $true }
                    "pibatch" { $process = $true }
                    "pimodules" { $process = $true }
                    "pitransferrecords" { $process = $true }
                    "piuser" { $process = $true }
                    default { $process = $false }
                }

                if($process)
                {                    
                    # Remove piadmin: A(r,w) from the ACL
				    if($acl.Contains("piworld: a(r,w)")) { $securityWeakness = $true }
                    elseif($acl.Contains("piworld: a(r)")) { $securityWeakness = $true }
                    elseif($acl.Contains("piworld: a(w)")) { $securityWeakness = $true }
                }
                		
				# Increment the counter if a weakness has been discovered.
				if($securityWeakness)
				{
					$securityWeaknessCounter++
					if($securityWeaknessCounter -eq 1)
					{ $warningMessage = $dbName }
					else
					{ $warningMessage = $warningMessage + ", " + $dbName }
				}					
			}			
		}	
	
		# Check if the counter is 0 = compliant, 1 or more it is not compliant		
		if($securityWeaknessCounter -gt 0)
		{
			$result = $false
			if($securityWeaknessCounter -eq 1)
			{ $warningMessage = "The following database: " + $warningMessage + " presents a weakness." }
			else
			{ $warningMessage = "The following databases: " + $warningMessage + " present weaknesses." }
		}
		else { $result = $true }	
	}
	catch
	{ $result = "N/A" }	
		
	# Define the results in the audit table
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20001" `
										-ain "PI Data Archive Table Security" -aiv $result `
										-msg $warningMessage `
										-Group1 "PI System" -Group2 "PI Data Archive" -Group3 "DB Security" `
										-Severity "Moderate"																		
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPIAdminTrustsDisabled
{
<#  
.SYNOPSIS
AU20002 - PI Admin Trusts Disabled Check
.DESCRIPTION
Audit ID: AU20002
Audit Check Name: PI Admin Trusts Disabled
Category: Severe
Compliance: Trust login should be disabled.
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
		$securityValidationCounter = 0
		$securityBits = 0								
											
		# Execute the PIConfig script.
		$outputFileContent = Invoke-PISysAudit_PIConfigScript -f "CheckPIAdminTrustsDisabled.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel						
		
		# Validate rules
		
		# Example of output.
		# piadmin,24		
		
		# Read each line to find the one containing the token to replace.
		foreach($line in $outputFileContent)
		{								
			# First line only.
			$tokens = $line.Split(",")
			$securityBits = [int16]$tokens[1]
			break
		}
		
		#Look for piadmin with identid=1
		# Requires:
		#	- explicit login disabled (bit5=16)
		#	- deletion disabled (bit4=8)
		#	- trust login disabled (bit3=4)
		if ( $securityBits -band 4 ) { $securityValidationCounter++ }
		if ( $securityBits -band 8 ) { $securityValidationCounter++ }
		if ( $securityBits -band 16 ) { $securityValidationCounter++ }
		
		# Check if the counter is 3 = compliant, 2 or less it is not compliant
		if($securityValidationCounter -eq 3) { $result = $true } else { $result = $false }	
	}
	catch
	{ $result = "N/A" }	
	
	#......................................
	# Define the results in the audit table	
	#......................................				
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20002" `
										-ain "PI Admin Trusts Disabled" -aiv $result `
										-Group1 "PI System" -Group2 "Trusts" `
										-Severity "Severe"																		
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPIServerSubSysVersions
{
<#  
.SYNOPSIS
AU20003 - PI Data Archive SubSystem Version Check
.DESCRIPTION
Audit ID: AU20003
Audit Check Name: PI Data Archive SubSystem Version
Category: Severe
Compliance: Version should be higher than 3.4.380.36.
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
		# Execute the piversion CLU.
		$outputFileContent = Invoke-PISysAudit_PIVersionCommand -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel	
				
		# Validate rules		
		
		# Example of output.	
		# Installation version,3.4.390.16
		# Installation binaries,64-bit
		# PI Build Name,390_Release_20120924.1
		# --------------------------------
		# C:\Program Files\PI\adm\apisnap.exe,Release Branch,3.4.390.16
		# C:\Program Files\PI\adm\ipisql.exe,Release Branch,3.4.390.16
		# ...
		# C:\Program Files\PI\bin\piaflink.exe,Release Branch,3.4.390.16
		# C:\Program Files\PI\bin\pialarm.exe,Release Branch,3.4.390.16
		# ...

		# Read each line to find the one containing the token to replace.	
		$result = $false
		foreach($line in $OutputFileContent)
		{								
			if($line.Contains("Installation version"))
			{								
				$tokens = $line.Split(",")
				$installationVersion  = $tokens[1]						
			}		
			elseif($line.Contains("Installation binaries"))
			{								
				$tokens = $line.Split(",")
				$installationBinaries  = $tokens[1]						
			}
			elseif($line.Contains("PI Build Name"))
			{								
				$tokens = $line.Split(",")
				$buildName  = $tokens[1]						
			}
		}
		
		$result = $false
		$installVersionTokens = $installationVersion.Split(".")
		# Form an integer value with all the version tokens.
		[string]$temp = $InstallVersionTokens[0] + $installVersionTokens[1] + $installVersionTokens[2] + $installVersionTokens[3]
		$installVersionInt64 = [Convert]::ToInt64($temp)	
		
		# Not compliant if under 3.4.380.36 version
		# Warn if 3.4.380.36 or 3.4.385.59 version	
		$result = $true
		$warningMessage = ""
		if ($installVersionInt64 -lt 3438036) { $result = $false}
		if ($installVersionInt64 -eq 3438036) { $result = $false; $warningMessage = "Upgrading to 3.4.390.16 is recommended." }
		if ($installVersionInt64 -eq 3438559) { $result = $false; $warningMessage = "Upgrading to 3.4.390.16 is recommended." }		
	}
	catch
	{ $Result = "N/A" }	
	
	# Define the results in the audit table
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20003" `
										-ain "PI Server SubSystem Versions" -aiv $result `
										-msg $warningMessage `
										-Group1 "PI System" -Group2 "PI Data Archive" -Group3 "PI SubSystems" `
										-Severity "Severe"									
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckEditDays
{
<#  
.SYNOPSIS
AU20004 - Check Edit Days
.DESCRIPTION
Audit ID: AU20004
Audit Check Name: Edit Days
Category: Moderate
Compliance: Greater than zero is a pass.
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
		# Execute the PIConfig script.
		$outputFileContent = Invoke-PISysAudit_PIConfigScript -f "CheckEditDays.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel																						
		
		# Validate rules	
	
		# Example of output.
		# if the file is empty, it means it is configure to default value of 1
		# otherwise the file would contain Autotrustconfig,<value>

		# Read each line to find the one containing the token to replace.		
		$valueFound = $false
		foreach($line in $outputFileContent)
		{								
			# Skip line if not containing the value autotrustconfig.
			if($line.ToLower().Contains("editdays"))
			{
				# Set the flag.
				$valueFound = $true
				# Find the delimiter
				$tokens = $line.Split(",")
	
				if($tokens[1] -eq 0) { $result = $false }
				else { $result = $true }
				break								
			}			
		}
		# The default value is set to 0 which is not compliant.
		if($valueFound -eq $false) { $result = $true }		
	}
	catch
	{ $result = "N/A" }	
			
	# Define the results in the audit table												
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20004" `
										-ain "Edit Days" -aiv $result `
										-Group1 "PI System" -Group2 "PI Data Archive" `
										-Severity "Severe"												
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckAutoTrustConfig
{
<#  
.SYNOPSIS
AU20005 - Auto Trust Configuration
.DESCRIPTION
Audit ID: AU20005
Audit Check Name: Auto Trust Configuration
Category: Moderate
Compliance: Should be part of a domain.
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
		# Execute the PIConfig script.
		$outputFileContent = Invoke-PISysAudit_PIConfigScript -f "CheckAutoTrustConfig.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel																						
																		
		# Validate rules	
	
		# Example of output.
		# if the file is empty, it means it is configure to default value of 1
		# otherwise the file would contain Autotrustconfig,<value>

		# Read each line to find the one containing the token to replace.		
		$valueFound = $false
		foreach($line in $outputFileContent)
		{								
			# Skip line if not containing the value autotrustconfig.
			if($line.ToLower().Contains("autotrustconfig"))
			{
				# Set the flag.
				$valueFound = $true
				# Find the delimiter
				$tokens = $line.Split(",")
				
				# 0 - Do not automatically create any PI Trust entries.
				# 0x01 - Create the trust entry for the loopback IP address 127.0.0.1
				# 0x02 - Create the trust entry for the "localhost" hostname
				# 0x04 - Create the trust entry for the IP address
				# 0x08 - Create the trust entry for the short hostname
				# 0x10 - Create the trust entry for the FQDN hostname
				# 0x1F - Create the old (pre 3.4.370.x) trust entries
				if($tokens[1] -le 1) { $result = $true }
				else { $result = $false }
				break								
			}			
		}
		# The default value is set to 1 which is compliant.
		if($valueFound -eq $false) { $result = $true }		
	}
	catch
	{ $result = "N/A" }	
			
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20005" `
										-ain "Auto Trust Configuration" -aiv $result `
										-Group1 "PI System" -Group2 "PI Data Archive" -Group3 "Trusts" `
										-Severity "Severe"	
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckExpensiveQueryProtection
{
<#  
.SYNOPSIS
AU20006 - Expensive Query Protection Check
.DESCRIPTION
Audit ID: AU20006
Audit Check Name: Expensive Query Protection
Category: Severe
Compliance: Value must be between 60 and 300.
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
		$securityValidationCounter = 0
		$securityBits = 0								
										
		# Execute the piversion CLU.
		$outputFileContent = Invoke-PISysAudit_PIVersionCommand -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel	
		
		# Validate rules		
		
		# Example of output.	
		# Installation version,3.4.390.16
		# Installation binaries,64-bit
		# PI Build Name,390_Release_20120924.1
		# --------------------------------
		# C:\Program Files\PI\adm\apisnap.exe,Release Branch,3.4.390.16
		# C:\Program Files\PI\adm\ipisql.exe,Release Branch,3.4.390.16
		# ...
		# C:\Program Files\PI\bin\piaflink.exe,Release Branch,3.4.390.16
		# C:\Program Files\PI\bin\pialarm.exe,Release Branch,3.4.390.16
		# ...

		# Read each line to find the one containing the token to replace.	
		$result = $false
		foreach($line in $OutputFileContent)
		{								
			if($line.Contains("Installation version"))
			{								
				$tokens = $line.Split(",")
				$installationVersion  = $tokens[1]						
			}					
		}
		$installVersionTokens = $installationVersion.Split(".")
		# Form an integer value with all the version tokens.
		[string]$temp = $InstallVersionTokens[0] + $installVersionTokens[1] + $installVersionTokens[2] + $installVersionTokens[3]
		$installVersionInt64 = [Convert]::ToInt64($temp)
		
		
		# Execute the PIConfig script.
		$outputFileContent = Invoke-PISysAudit_PIConfigScript -f "CheckExpensiveQuery.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
						
		# Validate rules
		
		# Example of output.
		# if the file is empty, it means it is configure to default value of 0 if the piarchss
		# is prior to (KB 3224OSI8) 3.4.390.x, otherwise it is set to 260.		
		# otherwise the file would contain Archive_MaxQueryExecutionSec,<value>				
		
		# Read each line to find the one containing the token to replace.
		$valueFound = $false
		foreach($line in $outputFileContent)
		{								
			if($line.ToLower().Contains("archive_maxqueryexecutionsec"))
			{				
				# First line only.
				$tokens = $line.Split(",")
				$timeout = [int16]$tokens[1]
				$valueFound = $true
				break
			}
		}			
						
		# Default value for PI Server prior to 3.4.390.16 was 0
		# Check if the timeout setting is between 60 and 300.
		if(($valueFound -eq $false) -and ($installVersionInt64 -lt 3439016)) { $result = $false }
		elseif(($valueFound -eq $false) -and ($installVersionInt64 -ge 3439016)) { $result = $true }				
		elseif($valueFound -and ($timeout -ge 60) -and ($timeout -le 300)) { $result = $true }
		else { $result = $false }	
	}
	catch
	{ $result = "N/A" }	
	
	#......................................
	# Define the results in the audit table	
	#......................................				
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20006" `
										-ain "Expensive Query Protection" -aiv $result `
										-Group1 "PI System" -Group2 "PI Data Archive" -Group3 "PI Archive SubSystem" `
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



function Get-PISysAudit_CheckExplicitLoginDisabled
{
<#  
.SYNOPSIS
AU20007 - Check if the explicit login is disabled
.DESCRIPTION
Audit ID: AU20007
Audit Check Name: Explicit login disabled
Category: Severe
Compliance: Value must be greater than 3
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
		# Execute the PIConfig script.
		$outputFileContent = Invoke-PISysAudit_PIConfigScript -f "CheckPIServerAuthPolicy.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel						
		
		# Validate rules
		$ServerAuthPolicy = $outputFileContent
		if($ServerAuthPolicy -lt 3){$result = $false} else {$result =$true}

	}
	catch
	{ $result = "N/A" }	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20007" `
										-ain "Explicit login disabled" -aiv $result `
										-Group1 "PI System" -Group2 "PI Data Archive" `
										-Severity "Severe"								
}

END {}
#***************************
#End of exported function
#***************************
}


function Get-PISysAudit_CheckPIAdminUsage
{
<#  
.SYNOPSIS
AU20008 - Check if piadmin is not used
.DESCRIPTION
Audit ID: AU20008
Audit Check Name: piadmin is not used
Category: Severe
Compliance: Value must be empty
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
		# Execute the PIConfig scripts.
		$outputFileContentTrust = Invoke-PISysAudit_PIConfigScript -f "CheckPIAdminUsageInTrusts.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel	
																
		$outputFileContentMapping = Invoke-PISysAudit_PIConfigScript -f "CheckPIAdminUsageInMappings.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel						
																																
		# Validate rules
		#Check is piadmin is used in any mappings or trusts. If it is, list them in the output
		
		if(($outputFileContentTrust) -or ($outputFileContentMapping))
		{
			$result = $false 
			$message = "Trust(s) that present weaknesses: " + $outputFileContentTrust
			$message+= "`nMapping(s) that present weaknesses: " + $outputFileContentMapping
		} else {$result =$true}
			
	}
	catch
	{ $result = "N/A" }	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20008" `
										-ain "piadmin is not used" -aiv $result `
										-msg  $message `
										-Group1 "PI System" -Group2 "PI Data Archive" `
										-Severity "Severe"								
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckTrusts
{
<#  
.SYNOPSIS
AU20009 - Trusts checkup
.DESCRIPTION
Audit ID: AU20009
Audit Check Name: Trusts checkup
Category: Severe
Compliance: Any existing trusts should be only for PI API connections. These trusts should at a minimum be 2+ (app name specified). Warnings for open trusts.
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
		# Execute the PIConfig scripts.
				
	}
	catch
	{ $result = "N/A" }	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20009" `
										-ain "AU20009" -aiv $result `
										-msg "<Message>" `
										-Group1 "PI System" -Group2 "PI Data Archive" `
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
function Get-PISysAudit_TemplateAU2xxxx
{
<#  
.SYNOPSIS
AU2xxxx - <Name>
.DESCRIPTION
Audit ID: AU2xxxx
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
										-at $AuditTable "AU2xxxx" `
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
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary2
Export-ModuleMember Get-PISysAudit_CheckPIAdminTrustsDisabled
Export-ModuleMember Get-PISysAudit_CheckPIServerSubSysVersions
Export-ModuleMember Get-PISysAudit_CheckPIServerDBSecurity_PIWorldReadAccess
Export-ModuleMember Get-PISysAudit_CheckEditDays
Export-ModuleMember Get-PISysAudit_CheckAutoTrustConfig
Export-ModuleMember Get-PISysAudit_CheckExpensiveQueryProtection
Export-ModuleMember Get-PISysAudit_CheckExplicitLoginDisabled
Export-ModuleMember Get-PISysAudit_CheckPIAdminUsage
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU2xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU2xxxx