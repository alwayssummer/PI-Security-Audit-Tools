# Reload the module to make sure you are using the latest
$rootModuleDir = Split-Path $PSScriptRoot
if(Get-Module pisysaudit){remove-module pisysaudit}
$modulepath = $rootModuleDir + '\PISYSAUDIT.psd1'
Import-Module $modulepath

# Read the existing Help
$helpFilePath = $rootModuleDir + "\en-US\about_PISYSAUDIT.help.txt"
$helpFile = Get-Content $helpFilePath

# Initialize 
$newHelp = ""
$write = $true


# Loop through current contents
foreach ($line in $helpFile)
{
    if($write) {$newHelp += $line + "`r`n"}
	
	# Stop echoing when we reach the validations section, and instead retrieve from the cmdlet's metadata
    if($line.ToUpper().Contains("//BEGINSECTION - VALIDATIONS//"))
    {
            $write = $false
            
			# Get all the functions
            $libs = @()
            $libs += Get-PISysAudit_FunctionsFromLibrary1 
            $libs += Get-PISysAudit_FunctionsFromLibrary2 
            $libs += Get-PISysAudit_FunctionsFromLibrary3 
            $libs += Get-PISysAudit_FunctionsFromLibrary4 
            $libs += Get-PISysAudit_FunctionsFromLibrary5 

            foreach ($lib in $libs)
            {
				$fnsSorted = @()
                foreach($fn in $lib.Keys){ $fnsSorted += Get-Help $fn }
                # Keys get out of order so we need to sort them by ID (Synopsis is of form <ID> - <Name>)
				$fnsSorted = $fnsSorted | Select-Object * | Sort-Object Synopsis
				# now we can record each validation.
                foreach($fn in $fnsSorted){
					$fnHelp = Get-Help $fn.Name
					# Properly space the description and sanitize if of the html tags.
					$newHelp += "`r`n`t`t" + $fnHelp.Synopsis + "`r`n`t`t" + $($($($($fnHelp.Description.Text `
						-replace "`n","`r`n`t`t") -replace "<br/>","") -replace "</a>","") -replace '<a href=".*?">','') + "`r`n"
                }
            }
            $newHelp += "`r`n`t`t//ENDSECTION - VALIDATIONS//`r`n"
    }
	# Resume echoing in order to fill in the rest of the file.
    if($line.ToUpper().Contains("//ENDSECTION - VALIDATIONS//")){$write = $true}
}
$newHelp | Out-File $helpFilePath -Encoding ASCII