# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     CheckProcessPrivilege.ps1
# * Version:      1.0.0.8
# * Description:  External command.
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

[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(				
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[string]
		$PrivilegeToProcess,		
		[parameter(Mandatory=$false, Position=1, ParameterSetName = "Default")]
		[string]
		$ServiceName = "",		
		[parameter(Mandatory=$false, Position=2, ParameterSetName = "Default")]
		[string]
		$ProcessName = "",
		[parameter(Mandatory=$false, Position=3, ParameterSetName = "Default")]
		[int]
		$DBGLevel = 0)
# P/Invoke code.
$code = @'

using System; 
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Principal;
public class HelperPrivilege
{

enum TOKEN_INFORMATION_CLASS
{
TokenUser = 1,
TokenGroups,
TokenPrivileges,
TokenOwner,
TokenPrimaryGroup,
TokenDefaultDacl,
TokenSource,
TokenType,
TokenImpersonationLevel,
TokenStatistics,
TokenRestrictedSids,
TokenSessionId,
TokenGroupsAndPrivileges,
TokenSessionReference,
TokenSandBoxInert,
TokenAuditPolicy,
TokenOrigin
}

[StructLayout(LayoutKind.Sequential)]
struct LUID
{
public uint LowPart;
public int HighPart;
}

[StructLayout(LayoutKind.Sequential)]
struct LUID_AND_ATTRIBUTES
{
public LUID Luid;
public uint Attributes;
}

[StructLayout(LayoutKind.Sequential)]
struct TOKEN_PRIVILEGES
{
public uint Count;
}

[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
static extern bool OpenProcessToken(IntPtr ProcessHandle, int Access, ref IntPtr phToken);

[DllImport("advapi32.dll", SetLastError = true)]
static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName);

static public List<string> EnumRights(string processName)
{
uint length = 0;
bool res;            
const int TOKEN_QUERY = 0x00000008;
const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
const UInt32 SE_PRIVILEGE_USER_FOR_ACCESS = 0x80000000;
List<string> privilegesList = new List<string>();            
Process[] listOfProcesses = Process.GetProcessesByName(processName);
if (listOfProcesses.Length == 0)
{ privilegesList.Add("No Process"); }
else
{			
IntPtr htok = IntPtr.Zero;
bool retVal = OpenProcessToken(listOfProcesses[0].Handle, TOKEN_QUERY, ref htok);
res = GetTokenInformation(htok, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, length, out length);
IntPtr tokenInformation = Marshal.AllocHGlobal(unchecked((int)length));
res = GetTokenInformation(htok, TOKEN_INFORMATION_CLASS.TokenPrivileges, tokenInformation, length, out length);
if (res)
{
privilegesList.Add(listOfProcesses[0].Id.ToString());
privilegesList.Add(listOfProcesses[0].ProcessName);
TOKEN_PRIVILEGES privs = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_PRIVILEGES));
privilegesList.Add(privs.Count.ToString());
for (int i = 0; i < privs.Count; i++)
{
IntPtr ptr = new IntPtr(tokenInformation.ToInt64() + sizeof(uint) + i * Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)));
LUID_AND_ATTRIBUTES privInfo = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(ptr, typeof(LUID_AND_ATTRIBUTES));                    
StringBuilder name = new StringBuilder();
string value = "";
IntPtr luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LUID)));
Marshal.StructureToPtr(privInfo.Luid, luidPtr, false);
int size = 0;
LookupPrivilegeName(null, luidPtr, null, ref size);
name.EnsureCapacity(size);
LookupPrivilegeName(null, luidPtr, name, ref size);
if (privInfo.Attributes == 0)
{ value = "=Disabled"; }
if ((privInfo.Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED)
{
if ((privInfo.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
{ value = "=Default,Enabled"; }
else
{ value = "=Enabled"; }
}
if ((privInfo.Attributes & SE_PRIVILEGE_REMOVED) == SE_PRIVILEGE_REMOVED)
{ value = "=Removed"; }
if ((privInfo.Attributes & SE_PRIVILEGE_USER_FOR_ACCESS) == SE_PRIVILEGE_USER_FOR_ACCESS)
{ value = "=UsedforAccess"; } 						
Marshal.FreeHGlobal(luidPtr);
privilegesList.Add(name.ToString() + value);
}
}
Marshal.FreeHGlobal(tokenInformation);
}
return privilegesList;
}				
}

'@

if(($ServiceName -eq $null) -and ($ProcessName -eq $null))
{
	# Return the error message.
	$msg = "Reading privileges from the process failed. The syntax is: CheckProcessPrivilege.ps1 <Privilege Name> [<Service Name>] [<Process Name>]."
					 + " Cannot process two items at a time!"		
	Write-Host $msg
	return $null
}

if(!($ServiceName -eq ""))
{
	# Perform the WMI Query via an Invoke-Command to be able	
	# to pass the Class under a variable.
	$filterExpression = [string]::Format("name='{0}'", $ServiceName)
	$scriptBlockCmdTemplate = "Get-WMIObject -Class {0} -filter `"{1}`""			
	$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, "Win32_Service", $filterExpression)							
	$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
	$WMIObject = Invoke-Command -ScriptBlock $scriptBlock																
	$processID = $WMIObject.ProcessID		
	
	# Process with the p/invoke code.		
	$processNameToValidate = (Get-Process -ID $processID).Name
}

if(!($ProcessName -eq ""))
{ $processNameToValidate = $ProcessName }

# Call the C# code embedded in the script.
# Dynamically load the code in memory.
$dynamicType = Add-Type -TypeDefinition $code -PassThru -Language "CSharp"
$privilegesList = $dynamicType[0]::EnumRights($processNameToValidate)				
$privilegeFound = $null

# Validate if you need to show all privileges
if($PrivilegeToProcess.ToLower() -eq "all")
{
	if($DBGLevel -gt 0)
	{
		if($privilegesList[0].ToLower() -ne "no process")
		{
			$msg1 = "Results of listing process/service privileges"
			$msgTemplate = "Privileges ({0}) were found for {1} process (PID={2}):"
			$msg2 = [string]::Format($msgTemplate, $privilegesList[2], $privilegesList[1], $privilegesList[0])
		 }
		Write-Host $msg1
		Write-Host $msg2
		for($i = 3; $i -lt $privilegesList.Count; $i++)
		{ Write-Host $privilegesList[$i] }
	}
		
	# Return the list.
	return $privilegesList
}
else
{
	# Lookup all privileges returned
	foreach($currentPrivilege in $privilegesList)
	{
		# Validate if the one to validate is found
		$privilegeFound = $false
		for($i = 3; $i -lt $privilegesList.Count; $i++)
		{ 				
			if($privilegesList[$i].ToLower() -eq $PrivilegeToProcess.ToLower())
			{ $privilegeFound = $true }
		}
	}
}

return $privilegeFound