# PI-Security-Audit-Tools

## Contents
This project is a framework to baseline the security configuration of your PI System. This framework is built as a PowerShell module containing cmdlets to perform different calls to collect the data from the security settings of specified PI System components.
  
A series of PowerShell script files (*.psm1) form a single module named PI System Audit Module (or PISysAudit Module) once loaded. You will find one core script containing the collection logic and library scripts containing the validation logic for different topics such as best practices to harden the machine, PI Server, etc. The module exposes several cmdlets either used for the internal logic or the external interface with the end-user.

The PI System Audit Module (PISysAudit) requires PowerShell version 2 and later, it can be executed locally or remotely and make use of existing command line utilities to perform many tasks. This allows compatibility with many versions of the PI System.  

The current version of the PISysAudit module implements validations covering machine (AU1XXXX), PI Data Archive (AU2XXXX), PI AF Server (AU3XXXX), SQL Server (AU4XXXX) and PI Coresight Server (AU5XXXX) best practices with the PI System.  
 
_Validations:_
```
AU10001 - Machine: Domain Membership Check 
AU10002	- Machine: OS SKU  
AU10003	- Machine: Validate if Windows firewall is enabled  	
AU10004 - Machine: AppLocker state
AU10005 - Machine: UAC enabled
AU20001	- PI Data Archive: Table Security	
AU20002	- PI Data Archive: PI Admin Trusts Disabled	 
AU20003	- PI Data Archive: Subsystem Version  	
AU20004	- PI Data Archive: Edit Days  
AU20005	- PI Data Archive: Auto Trust Configuration	 
AU20006	- PI Data Archive: Expensive Query Protection
AU20007 - PI Data Archive: Check if explicit login is disabled
AU20008 - PI Data Archive: piadmin used in Mappings and Trusts
AU20009 - PI Data Archive: Service Principal Name check
AU30001	- PI AF Server: Service Account  
AU30002	- PI AF Server: Impersonation mode for AF Data Sets  
AU30003	- PI AF Server: Service Access  
AU30004 - PI AF Server: Plugin Verify Level
AU30005 - PI AF Server: File Extension Whitelist
AU30006 - PI AF Server: Version
AU30007 - PI AF Server: Service Principal Name Check
AU40001	- SQL Server: xp_CmdShell	 
AU40002	- SQL Server: Adhoc Queries	 
AU40003	- SQL Server: DB Mail XPs	 
AU40004	- SQL Server: OLE Automation Procedures	
AU50001	- Coresight: Version	 
AU50002	- Coresight: AppPools Identity Check	 
AU50003	- Coresight: SSL Configuration Check	 
AU50004	- Coresight: Service Principal Name Check	
```

## Getting Started

You can access the latest release version of the PI Security Audit Tools from the [Releases](https://github.com/osisoft/PI-Security-Audit-Tools/releases) section of this repository.  

SETUP INSTRUCTIONS:  
The PISysAudit module does not require installation; you only need to extract the package. You will need to import the module from the extracted location in order to use it. The file structure is the following:  
  * PISecurityAudit = Contains the module definition.
  * PISecurityAudit\Scripts\piconfig = Contains the piconfig scripts leveraged by the PI Data Archive validation checks.
  * PISecurityAudit\Scripts = Contains command line utilities or PS scripts needed by the PS module
  * PISecurityAudit\Export = Contains the generated reports
  * PISecurityAudit\pwd = Contains saved password files using strong encryption
  
For example, if you have decompressed the package inside your user folder (C:\users\<user>\documents\PISecurityAudit), you need to import the module the following:  
  
```
  Import-Module "C:\users\<user>\documents\PISecurityAudit\pisysaudit"
```

USAGE EXAMPLES:  
The audit is launched with the New-PISysAuditReport cmdlet (or you can use the alias: piaudit). Two examples are provided below to help you.
 
Example 1:  
Use the command below to launch an audit with all PI Server, AF Server and SQL Server components installed locally. It makes use of all default parameters to perform the audit.  

```
    piaudit
```

Example 2:  
Use the commands below to launch the audit with two PI Servers, one AF Server and one SQL Server components installed on different machines than the one used to launch the script.  

```
    $cpt = piauditparams $null "Computer1" "PIServer"  
    $cpt = piauditparams $cpt "Computer2" "PIServer"  
    $cpt = piauditparams $cpt "Computer3" "PIAFServer"
    $cpt = piauditparams $cpt "Computer4" "PICoresightServer"
    $cpt = piauditparams $cpt "Computer5" "SQLServer" -InstanceName "sqlexpress"  
    piaudit -cpt $cpt  
```

You get more details by invoking the help with the Get-Help cmdlet like the following:  
    
```
    Get-Help piaudit  
```
    
For full contextual help, giving examples and a description of each audit check, remediations for failed checks and references for further information, use the following:

```
    Get-Help about_PISYSAUDIT
```

You can also find several examples of commands and syntaxes for this module within examples.ps1 file (located in the ..\PISecurityAudit\Scripts folder).  

Check out the [Wiki](https://github.com/osisoft/PI-Security-Audit-Tools/wiki) for tutorials and more information on the project.

## Contributing

Please make sure that you read our general [Contribution Guidelines](https://github.com/osisoft/contributing) and agree with them.  These guidelines apply to all OSIsoft projects on GitHub.  

We welcome everyone to share enhancement requests, issues and contributions.  While all contributions will be considered by our team, we cannot accept any changes until they have been reviewed.  This is to ensure they are appropriate and aligned with the goals of the project.  We will make every effort to respond in a timely fashion, but please be patient during the review process.  

To help streamline the process, please make sure that you review our guidance with respect to [Submitting Pull Requests, Issues and Enhancement Requests](https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Submitting-Pull-Requests,-Issues-and-Enhancement-Requests) on our Wiki page.  

## Licensing  

Copyright 2016 OSIsoft, LLC.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   
Please see the file named [LICENSE.md](LICENSE.md).
