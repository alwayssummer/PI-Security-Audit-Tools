# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB2.psm1
# * Description:  Validation rules for PI Data Archive.
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
# Authors:  Jim Davidson, Bryan Owen and Mathieu Hamel from OSIsoft.
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
	# the PI Data Archive compliance.
	[System.Collections.HashTable]$listOfFunctions = @{}	
	$listOfFunctions.Add("Get-PISysAudit_CheckPIServerDBSecurity_PIWorldReadAccess", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPIServerSubSysVersions", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPIAdminTrustsDisabled", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckEditDays", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckAutoTrustConfig", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckExpensiveQueryProtection", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckExplicitLoginDisabled",1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPIAdminUsage",1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPISPN",1)
				
	# Return the list.
	return $listOfFunctions	
}

function Get-PISysAudit_CheckPIServerDBSecurity_PIWorldReadAccess
{
<#  
.SYNOPSIS
AU20001 - PI Data Archive Table Security Check
.DESCRIPTION
VALIDATION: examines the database security of the PI Data Archive and flags any 
ACLs that contain access for PIWorld as weak. <br/>
COMPLIANCE: remove PIWorld access from all database security ACLs.  Note that prior
removing PIWorld access, you need to evaluate which applications are relying on that 
access so that you can grant those applications access explicitly. 
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
	$msg = ""
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
                $securityWeakness = $false
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
					{ $warningMessage = $warningMessage + "; " + $dbName }
				}					
			}			
		}	
	
		# Check if the counter is 0 = compliant, 1 or more it is not compliant		
		if($securityWeaknessCounter -gt 0)
		{
			$result = $false
			if($securityWeaknessCounter -eq 1)
			{ $warningMessage = "The following database presents a weakness: " + $warningMessage + "." }
			else
			{ $warningMessage = "The following databases present weaknesses: " + $warningMessage + "." }
		}
		else 
		{ 
			$result = $true 
			$warningMessage = "No databases identified that present a weakness."
		}	
		$msg = $warningMessage
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
		
	# Define the results in the audit table
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20001" `
										-ain "PI Data Archive Table Security" -aiv $result `
										-msg $msg `
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
VALIDATION: verifies that the piadmin PI User cannot be used in a PI Trust. <br/>
COMPLIANCE: disable Trusts with piadmin.  This can be done by checking "User 
cannot be used in a Trust" in the Properties menu for the piadmin PI User.  To access
this menu open use the Idenitities, Users, & Groups plugin in PI SMT, navigate to the 
PI User tab, right click the piadmin entry and select Properties in the context menu.
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
	$msg = ""
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
		if($securityValidationCounter -eq 3) 
		{ 
			$result = $true 
			$msg = "The piadmin user cannot be assigned to a trust."
		} 
		else 
		{ 
			$result = $false 
			$msg = "The piadmin user can be assigned to a trust."
		}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	#......................................
	# Define the results in the audit table	
	#......................................				
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20002" `
										-ain "PI Admin Trusts Disabled" -aiv $result `
										-msg $msg `
										-Group1 "PI System" -Group2 "PI Data Archive" `
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
VALIDATION: verifies that the PI Data Archive is using the most recent release. <br/>  
COMPLIANCE: upgrade the PI Data Archive to the latest version, PI Data Archive 
2016 (3.4.400.1162).  For more information, see the "Upgrade a PI Data Archive Server" 
section of the PI Data Archive Installation and Upgrade Guide, Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-0BDEB1F5-C72F-4865-91F7-F3D38A2975BD ">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-0BDEB1F5-C72F-4865-91F7-F3D38A2975BD </a>
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
	$msg = ""
	$Severity = "Unknown"
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
		$upgradeMessage = "Upgrading to 3.4.400.1162 is recommended."
		if ($installVersionInt64 -ge 344001162) { $result = $true; $msg = "Version is compliant"; $Severity = "severe" }
		elseif ($installVersionInt64 -ge 3438036 -and $installVersionInt64 -lt 344001162 ) { $result = $false; $msg = $upgradeMessage; $Severity = "severe" }	
		elseif ($installVersionInt64 -lt 3438036) { $result = $false; $msg = $upgradeMessage; $Severity = "critical" }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20003" `
										-ain "PI Data Archive SubSystem Versions" -aiv $result `
										-msg $msg `
										-Group1 "PI System" -Group2 "PI Data Archive" -Group3 "PI Subsystems" `
										-Severity $Severity									
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
VALIDATION: verified that the Edit Days tuning parameter is set. <br/>
COMPLIANCE: set to a value greater than zero.  EditDays defines the number of past 
days where events can be modified in the Snapshot or Archive databases. A zero value means 
no time check is done.  For instructions to set EditDays, see "Modify the EditDays tuning 
parameter" section in the PI Data Archive System Management Guide:<br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-0865CC31-BF8C-4347-B717-15071ED51399 ">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-0865CC31-BF8C-4347-B717-15071ED51399 </a>
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
	$msg = ""
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
	
				if($tokens[1] -eq 0) 
				{ 
					$result = $false 
					$msg = "EditDays using non-compliant value of 0."
				}
				else 
				{ 
					$result = $true 
					$msg = "EditDays specified as a non-zero value."
				}
				break								
			}			
		}
		# The default value is set to 0 which is not compliant.
		if($valueFound -eq $false) 
		{ 
			$result = $false
			$msg = "EditDays not specified, using non-compliant default of 0."
		}		
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
			
	# Define the results in the audit table												
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20004" `
										-ain "Edit Days" -aiv $result `
										-msg $msg `
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
VALIDATION: verifies that the autotrustconfig tuning parameter is set to create 
either no trusts or a trust for the loopback automatically (127.0.0.1). <br/>
COMPLIANCE: set the autotrustconfig tuning parameter to a value of 0 (do not 
automatically create any PI Trust entries) or 1 (create the trust entry for the loopback 
IP address 127.0.0.1 only). 
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
	$msg = ""
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

				switch ($tokens[1])
				{
					0   { $description = "Does not automatically create any PI Trust entries."; break; }
					1   { $description = "Creates the trust entry for the loopback IP address 127.0.0.1"; break; }
					2   { $description = "Creates the trust entry for the `"localhost`" hostname"; break; }
					4   { $description = "Creates the trust entry for the IP address"; break; }
					8   { $description = "Creates the trust entry for the short hostname"; break; }
					16   { $description = "Creates the trust entry for the FQDN hostname"; break; }
					32   { $description = "Creates the old (pre 3.4.370.x) trust entries"; break; }
			
					default {$description = "Unknown configuration" }
				}

				if($tokens[1] -le 1) 
				{ 
					$result = $true 
					$msg = "Tuning parameter compliant: {0}"
				}
				else 
				{ 
					$result = $false
					$msg = "Tuning parameter not compliant: {0}" 
				}
				$msg = [string]::Format($msg, $description)
				break								
			}			
		}
		# The default value is set to 1 which is compliant.
		if($valueFound -eq $false) 
		{ 
			$result = $true 
			$msg = "Tuning parameter compliant: Create the trust entry for the loopback IP address 127.0.0.1"
		}		
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
			
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20005" `
										-ain "Auto Trust Configuration" -aiv $result `
										-msg $msg `
										-Group1 "PI System" -Group2 "PI Data Archive" -Group3 "Authentication" `
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
VALIDATION: verify that the PI Data Archive has protection against expensive queries. <br/>
COMPLIANCE: set the archive_maxqueryexecutionsec tuning parameter to a value between 60 
and 300.  For more information on this parameter and other that can protect against expensive 
queries, see the knowledgebase article 3224OSI8 <br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/KB/3224OSI8">https://techsupport.osisoft.com/Troubleshooting/KB/3224OSI8  </a>
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
	$msg = ""
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
						
		# Default value for PI Data Archive prior to 3.4.390.16 was 0
		# Check if the timeout setting is between 60 and 300.
		if(($valueFound -eq $false) -and ($installVersionInt64 -lt 3439016)) 
		{ 
			$result = $false 
			$msg = "Using the non-compliant default of 0."
		}
		elseif(($valueFound -eq $false) -and ($installVersionInt64 -ge 3439016)) 
		{ 
			$result = $true 
			$msg = "Using the compliant default of 260."
		}				
		elseif($valueFound -and ($timeout -ge 60) -and ($timeout -le 300)) 
		{ 
			$result = $true 
			$msg = "Using a compliant value of {0}."
			$msg = [string]::Format($msg, $timeout)
		}
		else 
		{ 
			$result = $false 
			$msg = "Using a non-compliant value of {0}."
			$msg = [string]::Format($msg, $timeout)
		}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	#......................................
	# Define the results in the audit table	
	#......................................				
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20006" `
										-ain "Expensive Query Protection" -aiv $result `
										-msg $msg `
										-Group1 "PI System" -Group2 "PI Data Archive" -Group3 "PI Archive Subsystem" `
										-Severity "Severe"																		
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckExplicitLoginDisabled
{
<#  
.SYNOPSIS
AU20007 - Check if the explicit login is disabled
.DESCRIPTION
VALIDATION: verifies that explicit login is disabled as an authentication protocol. <br/>  
COMPLIANCE: set the tuning parameter Server_AuthenticationPolicy to a value greater than 3.  
This is equivalent to the third notch, "Disable explicit login", or higher on the Security 
Settings plugin in PI SMT.  For more information, see "Security Best Practice #2" and "Security 
Best Practice #3" in KB00833. <br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/KB/KB00833">https://techsupport.osisoft.com/Troubleshooting/KB/KB00833 </a>
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
	$msg = ""

	try
	{		
		# Execute the PIConfig script.
		$outputFileContent = Invoke-PISysAudit_PIConfigScript -f "CheckPIServerAuthPolicy.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel						
		
		# Validate rules
		$ServerAuthPolicy = $outputFileContent[0]
		
		switch ($ServerAuthPolicy)
				{
					0   { $description = "All authentication options enabled."; break; }
					2   { $description = "Explicit logins for users with blank passwords disabled."; break; }
					3   { $description = "Explicit logins disabled."; break; }
					19   { $description = "Explicit logins and SDK Trusts disabled."; break; }
					51   { $description = "All trusts and explicit login disabled."; break; }
			
					default {$description = "Unrecognized configuration" }
				}
		
		if($ServerAuthPolicy -lt 3)
		{
			$result = $false
			$msg = "Using non-compliant policy: {0}"
		} 
		else 
		{
			$result = $true
			$msg = "Using compliant policy: {0}"
		}
		$msg = [string]::Format($msg, $description)

	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20007" `
										-ain "Explicit login disabled" -aiv $result `
										-msg $msg `
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
VALIDATION: verifies that piadmin is not used in trusts or mappings. <br/>
COMPLIANCE: replace any trusts or mappings that use piadmin with a mapping or trust to a
PI Identity with appropriate privilege for the applications that will use it.  For more 
information, see "Security Best Practice" #4 in KB00833: <br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/KB/KB00833 ">https://techsupport.osisoft.com/Troubleshooting/KB/KB00833 </a>
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
	$msg = ""
	$weakTrustList = ""
	$weakMappingList = ""
	try
	{		
		# Execute the PIConfig scripts.
		$outputFileContentTrust = Invoke-PISysAudit_PIConfigScript -f "CheckPIAdminUsageInTrusts.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel	
																
		$outputFileContentMapping = Invoke-PISysAudit_PIConfigScript -f "CheckPIAdminUsageInMappings.dif" `
																-lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel						
		
		# Filtering out piconfig exit messages from output
		foreach($line in $outputFileContentTrust)
		{
			# Lines with delimiter have content of interest.
			if($line.Contains("^"))
			{
				$weakTrustList += $line.SubString(0, $line.IndexOf("^")) + "; "
			}
		}
		foreach($line in $outputFileContentMapping)
		{
			# Lines with delimiter have content of interest.
			if($line.Contains("^"))
			{
				$weakMappingList += $line.SubString(0, $line.IndexOf("^")) + "; "
			}
		}
																															
		# Validate rules
		# Check is piadmin is used in any mappings or trusts. If it is, list them in the output
		
		if(($weakTrustList) -or ($weakMappingList))
		{
			$result = $false 
			$msg = "Trust(s) that present weaknesses: " + $weakTrustList
			$msg += "`nMapping(s) that present weaknesses: " + $weakMappingList
		} 
		else 
		{
			$result =$true
			$msg = "No Trust(s) or Mapping(s) identified as weaknesses."
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20008" `
										-ain "piadmin is not used" -aiv $result `
										-msg  $msg `
										-Group1 "PI System" -Group2 "PI Data Archive" `
										-Severity "Severe"								
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPISPN
{
<#  
.SYNOPSIS
AU20009 - Check PI Server SPN
.DESCRIPTION
VALIDATION: Checks PI Data Archive SPN assignment.<br/>
COMPLIANCE: PI Data Archive SPNs exist and are assigned to the pinetmgr Service account. 
This makes Kerberos Authentication possible.  For more information, see "PI and Kerberos 
authentication" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-531FFEC4-9BBB-4CA0-9CE7-7434B21EA06D">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-531FFEC4-9BBB-4CA0-9CE7-7434B21EA06D </a>
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
	$msg = ""
	try
	{		
		$serviceType = "piserver"
		$serviceName = "pinetmgr"

		$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

		If ($result) 
		{ 
			$msg = "The Service Principal Name exists and it is assigned to the correct Service Account."
		} 
		Else 
		{ 
			$msg = "The Service Principal Name does NOT exist or is NOT assigned to the correct Service Account."
		}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20009" `
										-ain "PI Data Archive SPN Check" -aiv $result `
										-msg $msg `
										-Group1 "PI System" -Group2 "PI Data Archive"`
										-Severity "Moderate"								
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
AU20010 - Trust configuration strength
.DESCRIPTION
Audit ID: AU20010
Audit Check Name: Trust configuration strength
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
	$msg = ""
	try
	{		
		# Execute the PIConfig scripts.
				
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU20010" `
										-ain "Trust configuration strength" -aiv $result `
										-msg $msg `
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
VALIDATION: <Enter what the verification checks>
COMPLIANCE: <Enter what it needs to be compliant>
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
	$msg = ""
	try
	{		
		# Enter routine.			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU2xxxx" `
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
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary2
Export-ModuleMember Get-PISysAudit_CheckPIAdminTrustsDisabled
Export-ModuleMember Get-PISysAudit_CheckPIServerSubSysVersions
Export-ModuleMember Get-PISysAudit_CheckPIServerDBSecurity_PIWorldReadAccess
Export-ModuleMember Get-PISysAudit_CheckEditDays
Export-ModuleMember Get-PISysAudit_CheckAutoTrustConfig
Export-ModuleMember Get-PISysAudit_CheckExpensiveQueryProtection
Export-ModuleMember Get-PISysAudit_CheckExplicitLoginDisabled
Export-ModuleMember Get-PISysAudit_CheckPIAdminUsage
Export-ModuleMember Get-PISysAudit_CheckPISPN
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU2xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU2xxxx