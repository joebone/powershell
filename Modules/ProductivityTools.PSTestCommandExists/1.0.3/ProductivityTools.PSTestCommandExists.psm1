
function Test-CommandExists {
	[CmdletBinding()]
	param($Name)

	$oldPreference = $ErrorActionPreference
	Write-Verbose "Previous ErrorActionPreference: $ErrorActionPreference"
	$ErrorActionPreference = "Stop"
	Write-Verbose "Set ErrorActionPreference to 'Stop'"

	try {
		$command=Get-Command $Name
		Write-Verbose "Command Exists $command"
		return $true
	}
	catch {
		Write-Verbose "Command $Name does not exist" 
		return $false
	}
	finally {
		$ErrorActionPreference=$oldPreference
		Write-Verbose "Restore ErrorActionPreference: $ErrorActionPreference"
	}
}

Export-ModuleMember Test-CommandExists