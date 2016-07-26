# ************************************************************************
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

# Import the module
# This can be recorded inside your profile (.ps1) file
$modulePath = "<path to PISYSAUDIT folder>"
Import-Module $modulePath

# Example 1
# Example with all local and default parameters
piaudit

# Example 2
# Example with specific parameters for each server/PI Component.
$cpt = piauditparams $null "myPIServer" "PIDataArchive"
$cpt = piauditparams $cpt "myPIAFServer" "PIAFServer"
$cpt = piauditparams $cpt "mySQLServer" "SQLServer" -InstanceName "myinstance" # -IntegratedSecurity $false -user "sa" -pf "p1.dat"
$cpt = piauditparams $cpt "myCoresight" "PICoresightServer"
piaudit -cpt $cpt

# Example 3
# Save the password on disk
pwdondisk

# Example with specific parameters for each server/PI Component.
# Use the name of the password file to pass to use SQL Account authentication.
$cpt = piauditparams $null "myPIServer" "PIDataArchive"
$cpt = piauditparams $cpt "myPIAFServer" "PIAFServer"
$cpt = piauditparams $cpt "mySQLServer" "SQLServer" -InstanceName "myinstance" -IntegratedSecurity $false -user "sa" -pf "p1.dat"
$cpt = piauditparams $cpt "myCoresight" "PICoresightServer"
piaudit -cpt $cpt

# Example 4
# Example with specific parameters for each server/PI Component.
# You will be prompted for entering a password for the SQL Account authentication.
$cpt = piauditparams $null "myPIServer" "PIDataArchive"
$cpt = piauditparams $cpt "myPIAFServer" "PIAFServer"
$cpt = piauditparams $cpt "mySQLServer" "SQLServer" -InstanceName "myinstance" -IntegratedSecurity $false -user "sa"
$cpt = piauditparams $cpt "myCoresight" "PICoresightServer"
piaudit -cpt $cpt

# Example 5
# Disable the obfuscation of computer names in the report
piaudit -obf $false 

# Example 6
# Disable the output to screen when used with scheduled task.
piaudit -ShowUI $false 