#region Imports / other files
# loader.psm1

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# $DefaultUser = 'Joe@JOEBONE-LAPTOP'
$DefaultUser = $env:UserName + '@' + $env:COMPUTERNAME;

$hosts = "C:\Windows\System32\drivers\etc\hosts"
$appdata = "$HOME/appdata/local"
$temp = "$HOME/appdata/local/temp"
$tmp = "$HOME/appdata/local/temp"
$def =  $MyInvocation.MyCommand.Definition
$scriptName = $MyInvocation.MyCommand.Name

$scriptPath = $def -replace "\\$scriptName", "" # split-path -parent $def # split-path is hella slow
$profilePath = $scriptPath

Set-Item -force function:DoUpdates {
	#Param (
		#[string]$pp
	#)

	if(-not $isAdmin) {
		Write-Host "This function must be run in admin mode. Run GoAdmin to elevate";
		return;
	}

	try {
		Write-Host "Updating windows store apps"
		# $namespaceName = "root\cimv2\mdm\dmmap"
		# $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
		# $wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
		# $result = $wmiObj.UpdateScanMethod()

		$AppMgmt = Get-WmiObject -Namespace "MDM\_EnterpriseModernAppManagement\_AppManagement01" -Class "MDM\_EnterpriseModernAppManagement\_AppManagement01"
		$AppMgmt.UpdateScanMethod()
	} catch {}

	try{
		Write-Host "Updating scoop"
		scoop update *
		scoop cache rm *
		scoop cleanup *
	} catch {}

	try{
		Write-Host "Updating chocolatey"
		choco upgrade all
		choco-cleaner.bat
	} catch {}

	try {
		Write-Host "Updating Visual studio.."
		Start-Process -Wait -FilePath  "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" -ArgumentList "update --passive --norestart --installpath ""C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise"""
	} catch {}

	try {
		Write-Host "Checking for windows updates"
		InstallModuleIfAbsent PSWindowsUpdate
		Get-WindowsUpdate
		Install-WindowsUpdate  -AcceptAll -MicrosoftUpdate
	} catch {}
}


Set-Item -force function:CleanDocker {
	docker system prune --all --force --volumes 

	wsl -d docker-desktop fstrim /
	wsl -d docker-desktop-data fstrim /
	Write-Host ">>> Compacting Docker VHD";
	
	$dockerProc = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
	if ($dockerProc) {
		$dockerProc.CloseMainWindow()
		$dockerProc | Stop-Process -Force
	}
	Stop-Service *docker*
	
	# Clear WSL space, compact the vhds?
	wsl.exe --list --verbose
	#wsl --terminate <DistributionName>
	wsl --shutdown 
	# $pathToVHD = $("$Env:LOCALAPPDATA\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc")


	#byebye all docker data
	wslconfig /unregister docker-desktop
	wslconfig /unregister docker-desktop-data

	# 	# To Move WSL distro:
	#Function WSL-SetDefaultUser ($distro, $user) { Get-ItemProperty Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Lxss\*\ DistributionName | Where-Object -Property DistributionName -eq $distro | Set-ItemProperty -Name DefaultUid -Value ((wsl -d $distro -u $user -e id -u) | Out-String); };

	# wsl --export Ubuntu-18.04 .\ubuntu.tar
	# wsl --unregister Ubuntu-18.04
	# wsl --import Ubuntu . ubuntu.tar
	# wsl --set-default Ubuntu
	# sc stop LxssManager
	# sc start LxssManager
	# # ubuntu config --default-user joebone
	# #LxRunOffline.exe set-uid -n Ubuntu -v joebone

	# WSL-SetDefaultUser Ubuntu joebone

	$pathToVHD = "C:\wsl\Ubuntu\ext4.vhdx" #/AppData/Local/Docker/wsl/data/ext4.vhdx
	# diskpart $pathToVHD 
	#select vdisk file="C:\Users\valorin\AppData\Local\Packages\WhitewaterFoundryLtd.Co.16571368D6CFF_kd...\LocalState\ext4.vhdx"
	#DISKPART> compact vdisk

	Optimize-VHD -Path "$env:LOCALAPPDATA\Docker\wsl\data\ext4.vhdx" -Mode Full
	Write-Host ">>> Starting docker again"
	restart-service *docker*
	Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
	
}

Function Get-FreeSpace {
	return (Get-CimInstance -Class CIM_LogicalDisk)[0].FreeSpace / 1gb;
}
Function Get-DiskSize {
	$Disks = @()
	$DiskObjects = Get-CimInstance -Class CIM_LogicalDisk
	$DiskObjects | ForEach-Object {
	  $Disk = New-Object PSObject -Property @{
		Name           = $_.Name
		Capacity       = [math]::Round($_.Size / 1gb, 2)
		FreeSpace      = [math]::Round($_.FreeSpace / 1gb, 2)
		FreePercentage = [math]::Round($_.FreeSpace / $_.Size * 100, 1)
	  }
	  $Disks += $Disk
	}
	Write-Output $Disks | Sort-Object Name
  }

Get-DiskSize | Format-Table Name,@{L='Capacity (GB)';E={$_.Capacity}},@{L='FreeSpace (GB)';E={$_.FreeSpace}},@{L='FreePercentage (%)';E={$_.FreePercentage}}

Set-Item -force function:cleanpackagescache {
	#Param (
		#[string]$server
	#)

	$originalFreeSpace = Get-FreeSpace
	$preSize = Get-DiskSize

	Write-Host "there is some duplication with the other command, 'ClearCaches'"
	if(-not $isAdmin) {
		Write-Host "This function must be run in admin mode. Run GoAdmin to elevate";
		return;
	}

	$confirmation = Read-Host "This will irrevocably delete docker volumes, images, package caches for scoop and chocolatey, etc. (y/n)"
	if (-not ($confirmation -eq 'y')) {
		# proceed
		Write-Host "Abandoning cleanup..."
		return;
	}

	Write-Host ">>> Cleaning npm cache..`r`n"
	npm cache clean -force # npm folders

	Write-Host ">>> Cleaning yarn cache..`r`n"
	yarn cache clean -force # yarn...

	Write-Host ">>> Cleaning dotnet nuget cache..`r`n"
	dotnet nuget locals all --clear

	$hadToInstallHyperV = $false
	if (-not (Test-CommandExists Optimize-VHD)) {
		# InstallModuleIfAbsent Hyper-V
		Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
		$hadToInstallHyperV = $true
		#Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Tools-All
		#Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell
	}
	Write-Host ">>> Cleaning docker..`r`n"
	CleanDocker

	if($hadToInstallHyperV) {
		Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
	}

	Write-Host ">>> Cleaning chocolatey`r`n"
	try {
		if(-not (choco list -lo | ? { $_ -like 'choco-cleaner*'  })) {
			Write-Host "Choco cleaner not installed, installing..";
			choco install choco-cleaner
		} else {
			choco upgrade choco-cleaner
		}
		choco-cleaner.bat
	} 
	catch {
		Write-Host "Error Running choco cleaner"
	}

	Write-Host "Cleaning scoop"
	try {
		scoop cache rm *
		scoop cleanup *
	} catch {
		Write-Host "Error cleaning up scoop."
	}

	Write-Host "Cleaning up windows components"
	try {
		schtasks.exe /Run /TN "\Microsoft\Windows\Servicing\StartComponentCleanup"
		Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase /SPSuperseded
		c:\windows\SYSTEM32\cleanmgr.exe /verylowdisk /setup /d c 
	} catch {
		
	}

	Write-Host "Getting user list..."
	Get-ChildItem C:\Users | Select-Object Name | Export-Csv -Path C:\users\$env:USERNAME\users.csv -NoTypeInformation
	$userlist = Test-Path C:\users\$env:USERNAME\users.csv

	if ($userlist) {
		Write-Host "Cleaning Firefox Cache"
		
		Import-CSV -Path C:\users\$env:USERNAME\users.csv -Header Name | ForEach-Object {
				Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache\*" -Recurse -Force -EA SilentlyContinue -Verbose
				Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache\*.*" -Recurse -Force -EA SilentlyContinue -Verbose
				Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cache2\entries\*.*" -Recurse -Force -EA SilentlyContinue -Verbose
				Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\thumbnails\*" -Recurse -Force -EA SilentlyContinue -Verbose
				# Remove-Item -path C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\cookies.sqlite -Recurse -Force -EA SilentlyContinue -Verbose
				Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\webappsstore.sqlite" -Recurse -Force -EA SilentlyContinue -Verbose
				Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Mozilla\Firefox\Profiles\*.default\chromeappsstore.sqlite" -Recurse -Force -EA SilentlyContinue -Verbose
		}
		Write-Host -ForegroundColor yellow "Done..."

		Write-Host "Cleaning Google Chrome cache"
		Import-CSV -Path C:\users\$env:USERNAME\users.csv -Header Name | ForEach-Object {
			Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Cache2\entries\*" -Recurse -Force -EA SilentlyContinue 
			# Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies" -Recurse -Force -EA SilentlyContinue -Verbose
			Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Media Cache" -Recurse -Force -EA SilentlyContinue
			# Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies-Journal" -Recurse -Force -EA SilentlyContinue -Verbose
			# Comment out the following line to remove the Chrome Write Font Cache too.
			# Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Google\Chrome\User Data\Default\ChromeDWriteFontCache" -Recurse -Force -EA SilentlyContinue -Verbose
		}

		Write-Host "Cleaning IE Cache" 
		Import-CSV -Path C:\users\$env:USERNAME\users.csv | ForEach-Object {
            Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force -EA SilentlyContinue
			Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Windows\WER\*" -Recurse -Force -EA SilentlyContinue
		}

		Write-Host "Cleaning Edge Cache" 
		# https://blog.group-ib.com/forensics_edge
		Import-CSV -Path C:\users\$env:USERNAME\users.csv | ForEach-Object {
			Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Edge\User Data\**\Cache" -Recurse -Force -EA SilentlyContinue
			Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Edge\User Data\**\Code Cache" -Recurse -Force -EA SilentlyContinue 
			Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Edge\User Data\**\Cache Storage" -Recurse -Force  # ServiceWorker Cache
			Remove-Item -path "C:\Users\$($_.Name)\AppData\Local\Microsoft\Edge\User Data\**\Service Worker\CacheStorage" -Recurse -Force  # ServiceWorker Cache

		}

		Write-Host -ForegroundColor Green "All Browsers cache cleaned!"
	}

	Write-Host "Cleaning Temp folders..."
	# temp folder
	Push-Location
	Set-Location $env:TEMP 
	try {
		Get-ChildItem | Remove-Item -Recurse -Force
		Remove-Item -path "C:\Windows\Temp\*" -Recurse -Force -EA SilentlyContinue -Verbose
	} catch {

	}
	Pop-Location

	Write-Host "Emptying Recycle bin..."
	Remove-Item -Recurse -Force "$env:systemdrive\`$Recycle.bin"

	$postFreeSpace = Get-FreeSpace
	$postSize = Get-DiskSize

	Write-Host "Space freed: $([math]::Round($postFreeSpace - $originalFreeSpace, 2))gb"

	Write-Host "Waiting 10 seconds..."
	Start-Sleep 10

	Write-Host "Trimming C:"
	Optimize-Volume -DriveLetter C -ReTrim -Verbose
}

Set-Item -force function:RemoveJunkWindows10Apps {
	
	Import-Module Appx -UseWindowsPowerShell # powerhsell 7.1 broke compat with the winrt libraries, have to remote it to the older one
	$appname = @(
		"*BingWeather*"
		"*ZuneMusic*"
		"*ZuneVideo*"
		"*Print3D*",
		"*Messaging_2019*"
		"*CandyCrush*"
		"*MidiKeyboard*"

	)

	ForEach($app in $appname){
		#Get-AppxPackage -AllUsers | Remove-AppxPackage
		Write-Color `
		 		-Text "Removing App and provisioned package", "dism /online /Remove-ProvisionedAppxPackage /PackageName:$item", " then ", `
		 			"Remove-AppxPackage $item" `
		 		-Color Gray, Green, Gray, Green
		Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
		Get-AppxPackage -AllUsers -Name $app | Remove-AppxProvisionedPackage -ErrorAction SilentlyContinue
	}

	
	# Write-Host "To get a list of packages, run ""dism /online /Get-ProvisionedAppxPackages"""

	# InstallModuleIfAbsent Appx

	# $removable = (
	# 	"Microsoft.BingTravel_1.2.0.145_x86__8wekyb3d8bbwe",
	# 	"Microsoft.ZuneMusic_1.0.927.0_x86__8wekyb3d8bbwe",
	# 	"Microsoft.ZuneVideo_1.0.927.0_x86__8wekyb3d8bbwe",
	# 	"Microsoft.WindowsAlarms_2021.2101.28.0_neutral_~_8wekyb3d8bbwe",
	# 	"Microsoft.Print3D_3.3.791.0_neutral_~_8wekyb3d8bbwe",
	# 	"Microsoft.People_2020.901.1724.0_neutral_~_8wekyb3d8bbwe",
	# 	"Microsoft.MSPaint_2020.2009.30067.0_neutral_~_8wekyb3d8bbwe",
	# 	"Microsoft.MixedReality.Portal_2000.20111.1381.0_neutral_~_8wekyb3d8bbwe",
	# 	"Microsoft.MicrosoftSolitaireCollection_4.9.1252.0_neutral_~_8wekyb3d8bbwe",
	# 	"Microsoft.Microsoft3DViewer_2020.2010.15012.0_neutral_~_8wekyb3d8bbwe"
	# 	);

	# foreach ($item in $removable) {
	# 	Write-Color `
	# 		-Text "Executing ", "dism /online /Remove-ProvisionedAppxPackage /PackageName:$item", " then ", `
	# 			"Remove-AppxPackage $item" `
	# 		-Color Gray, Green, Gray, Green
		
	# 	$op = $(dism /online /Remove-ProvisionedAppxPackage /PackageName:$item)
	# 	Remove-AppxPackage $item

	# }

}

function reboot() {
	shutdown -t 0 -r
}

Set-Item -force function:ProfileTheProfile {
	WhyScriptNoGoBrrrr $profile;
	#. Measure-Script @PSBoundParameters |Sort-Object ExecutionTime |Select-Object -Last 5
	. Measure-Script $profile |Sort-Object -Descending ExecutionTime |Select-Object -First 10
	#Measure-Script $profile
}
function Initialize-Config() {
	# Get-Verb
	Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted   # Set Microsoft PowerShell Gallery to 'Trusted'
	GetAndCacheInstalledModules -force=$true
	installTools
}

function GetAndCacheInstalledModules($force = $false) {
	$file = "$scriptPath\moduleCache.json";
	if ($force -or (-not (gci $file | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1)}))) {
		Write-Host "Cache for installed modules is expired or force requested. Refreshing."
		$modules = Get-InstalledModule;
		$data = ($modules | ConvertTo-Json -Compress)
		$data | Out-File -FilePath $file
		$global:installedModules = $modules
		return $modules;
		# $CliXMLlength = [System.Management.Automation.PSSerializer]::Serialize($Object).Length
		# $JSONlength = ($Object | ConvertTo-Json -Compress).Length
		# $HashData = ($Object | ConvertTo-Hashtable | ConvertTo-HashString).Length
	}
	Write-Color -Text "Reading module data from cached file: ", $file -Color White, Red
	$jsondata = Get-Content -Raw -Path $file | ConvertFrom-Json

	$global:installedModules = $jsondata
	return $jsondata

}
function InstallModuleIfAbsent {
	param(
		[string]$name, 
		[Parameter(Mandatory = $false)][switch]$PreRelease = $false,
		[Parameter(Mandatory = $false)][string]$Repository = 'PSGallery',
		[Parameter(Mandatory = $false)][string]$PostInstall = ''
	)
	# -name posh-cli -Repository PSGallery -PostInstall "Install-TabCompletion"
	if(-not $global:installedModules) {
		# Cache list for multiple calls
		# $installedModules = Get-Module -ListAvailable
		# listavailable makes it HELLA slow
		# $installedModules = Get-Module
		$global:installedModules = GetAndCacheInstalledModules # Get-InstalledModule
	}
	# https://antjanus.com/blog/web-development-tutorials/how-to-grep-in-powershell/
	$searchString = "*$name*"
	if (-not($global:installedModules | Where-Object { $_.Name -Like $searchString	})) {
	#if (-not(Get-Module -ListAvailable -Name $name)) {
		Write-Host "  Module $name is absent > Install to current user.  " -ForegroundColor Black -BackgroundColor Yellow
		if ($PreRelease) {
			Install-Module $name -Scope CurrentUser -Force -AllowClobber -AllowPrerelease -Repository $Repository -SkipPublisherCheck
		}
		else {
			Install-Module $name -Scope CurrentUser -Force -AllowClobber -Repository $Repository -SkipPublisherCheck
		}

		if($PostInstall) {
			Invoke-Expression $PostInstall
		}
	}
	try { 
		Import-Module $name
	} 
	catch {
		Write-Host "Error importing $name"; 
	}

}

function GoAdmin { 
	if ($isAdmin) { Write-Host "Already in admin mode"; return ; }
	& Start-Process wt "/d . pwsh" –Verb RunAs; exit;
}
Set-Alias elevate GoAdmin
Set-Alias gosudo GoAdmin
Set-Alias which Get-Command
# Set-Alias where Get-Command

Set-Item -force function:ssh-copy-id {
	Param (
		[string]$server
	)
	if (-not ($server -like "*@*")) {
		$server = "root@$server";
	}
	Get-Content ~/.ssh/id_rsa.pub | ssh $server "mkdir ~/.ssh; cat >> ~/.ssh/authorized_keys"
}

#Export-ModuleMember -Function InstallModuleIfAbsent
########################################
#endregion

# $env:Path += ";C:\tools\cygwin\bin\"
# To install krew, download the exe from https://github.com/kubernetes-sigs/krew/releases , 
# then run .\krew install krew
$env:Path = "c:\bin;$(Resolve-Path ~)\scoop\shims;$(Resolve-Path ~)\.krew\bin;C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\;" + $env:Path; # after installing krew (https://github.com/kubernetes-sigs/krew/releases)

if (-not (Test-CommandExists node)) {
	Write-Color -Text "" -Color White;
	$vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Preview\MSBuild\Microsoft\VisualStudio\NodeJs"
	if (Test-Path $vsPath) {
		$env:Path += ";$vsPath";
		Write-Color -Text "", "Nodejs not detected ", " in path. Adding VS path to environment:", $vsPath -Color White, Red, White, Green;
	}
}

if (-not (Test-CommandExists rg)) {
	Write-Color -Text "ripgrep Not detected, installing...";
	scoop bucket add extras
	scoop install ripgrep
}

Write-Color -Text "Aliasing ", "grep ", "to ", "rg", " - ripgrep ftw (pipeline and inline mode supported)!" -Color White, Green, White, Green, White

Set-Alias grep rg


function DisableAV() {
	Write-Host @"
	Although Microsoft Defender offers a command to disable the antivirus, it's guarded by the Tamper Protection feature,
	 which you can only disable through the Virus & threat protection settings available in the Windows Security app.

	To disable the antivirus, turn off Tamper Protection.: 

	SYSINTERNALS TOOLS MUST Be INSTALLED FOR PSEXEC
"@


	try {
		#$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
		#$acl = Get-Acl $regPath
		#$acl
		#psexec.exe -i -s powershell.exe -noprofile Set-ItemProperty -Path $regPath -Name TamperProtection -Value 0 -Force
		#Start-process powershell.exe -credential 'SYSTEM' -NoNewWindow -ArgumentList '-noprofile -executionpolicy bypass', 'Set-ItemProperty -Path $regPath -Name TamperProtection -Value 0 -Force'
		Set-ItemProperty -Path $regPath -Name TamperProtection -Value 0 -Force

		#New-ItemProperty -Path $regPath -Name 'TamperProtection' -Value "0" -PropertyType DWORD -Force
		#You can go to the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features registry key, then Set TamperProtection  DWORD value to 0 for turning Off and 5 to on.

		Set-MpPreference -DisableRealtimeMonitoring $true

		#New-ItemProperty -Path $regPath -Name 'TamperProtection' -Value "5" -PropertyType DWORD -Force
		Set-ItemProperty -Path $regPath -Name TamperProtection -Value 5 -Force
		
	} catch {
		Start-Process explorer.exe windowsdefender:
	}
}


function DisplayInBytes($num) 
{
    $suffix = "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"
    $index = 0
    while ($num -gt 1kb) 
    {
        $num = $num / 1kb
        $index++
    } 

    "{0:N1} {1}" -f $num, $suffix[$index]
}
function Mem-Hogs { 
	# get-process | Where-Object { ($_.PM -gt 10000000000) -or ($_.VM -gt 10000000000) } 
	InstallModuleIfAbsent -name WindowsCompatibility # -Scope CurrentUser
	# Get-WmiObject WIN32_PROCESS | Sort-Object -Property ws -Descending | Select-Object -first 5 ProcessID,Name,WS
	$serial = Get-CimInstance win32_bios | select Serialnumber
	Write-Host "Windows Serial: $serial"
	Get-CimInstance WIN32_PROCESS | Sort-Object -Property ws -Descending | Select-Object -first 15 ProcessID,Name,WS | `
		 ForEach-Object { 
			 $dd = DisplayInBytes($_.WS);
			 $ObjectProperties = @{
				# Assuming you've assigned something to $Propriedad, $Users and $ErrorState above
				ProcessId	= $_.ProcessId
				Name       	= $_.Name
				WorkingSet 	= $dd
			}
			
			# Now create an object. 
			# When we just drop it in the pipeline like this, it gets assigned to $Objects
			New-Object psobject -Property $ObjectProperties
		}
		 #"{0:P}" -f $_.WS
}
Set-Alias free Mem-Hogs

#region Profile imports
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_format.ps1xml?view=powershell-7.1&viewFallbackFrom=powershell-6
InstallModuleIfAbsent -name Terminal-Icons
# InstallModuleIfAbsent -name ProductivityTools.PSTestCommandExists
InstallModuleIfAbsent -name PSWriteColor
# InstallModuleIfAbsent -name posh-git
# Import-Module Telnet # https://www.techtutsonline.com/powershell-alternative-telnet-command/

InstallModuleIfAbsent -name posh-cli -Repository PSGallery -PostInstall "Install-TabCompletion"
#Install-Module -Name posh-cli -Repository PSGallery
#https://github.com/JanDeDobbeleer/oh-my-posh
# InstallModuleIfAbsent -name oh-my-posh -PreRelease # These are done via Scoop
# InstallModuleIfAbsent -name PSKubectlCompletion

# Set-Theme Paradox # Darkblood | Agnoster | Paradox

#region PSReadline Options
######################################################################## PSReadLine Options
InstallModuleIfAbsent -name PSReadLine -PreRelease
Set-PSReadLineOption -HistoryNoDuplicates
Set-PSReadLineOption -HistorySearchCursorMovesToEnd
Set-PSReadLineOption -HistorySaveStyle SaveIncrementally
Set-PSReadLineOption -MaximumHistoryCount 4000
# history substring search
Set-PSReadlineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadlineKeyHandler -Key DownArrow -Function HistorySearchForward

# Tab completion
Set-PSReadlineKeyHandler -Chord 'Shift+Tab' -Function Complete
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete

##########################################################################

function pwd-clipboard () {
	$PWD.Path | CLIP
}
Set-Alias Copy-Path pwd-clipboard
Set-Alias copypath pwd-clipboard


###############################################################################

If (-Not (Test-Path Variable:PSise)) {
	# Only run this in the console and not in the ISE
	InstallModuleIfAbsent Get-ChildItemColor
	Import-Module Get-ChildItemColor
    
	Set-Alias l Get-ChildItem -option AllScope
	Set-Alias ls Get-ChildItemColorFormatWide -option AllScope
	Set-Alias ver $PSVersionTable
}

###############################################################################

InstallModuleIfAbsent ZLocation
Import-Module ZLocation
#endregion

#region Aliases
Set-Alias -Name k -Value kubectl
#endregion

#region kubectl aliases
# https://github.com/ohmyzsh/ohmyzsh/blob/master/plugins/kubectl/kubectl.plugin.zsh
#function k([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl $params }
function kg([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl get -o wide $params }
function kde([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl describe $params }
Set-Alias -Name kd -Value kde

function kwhystuck([Parameter(ValueFromRemainingArguments = $true)]$params) {
	if(-not $params) {
		$NAMESPACE = knscurrent
		Write-Output "No namespace specified, using current NS: $NAMESPACE"
	} else {
		$NAMESPACE = $params
	}

	$obj = & kubectl get namespace $(knscurrent) -o json | ConvertFrom-Json
	$candidate = $obj.status.conditions | Where-Object { $_.status -eq $true } 
	$crappy = $obj.status.conditions | Where-Object { $_.status -eq $false } 
	Write-Output "Unlikely candidates:"
	Write-Host -ForegroundColor Gray ($crappy | Format-Table | Out-String)
	Write-Output "Likely candidates:"
	Write-Host -ForegroundColor Red ($candidate | Format-List | Out-String)
	

	
	# & kubectl get namespace $(knscurrent) -o json |jq '.spec = {"finalizers":[]}' | ConvertFrom-Json -AsHashtable
	# & kubectl get namespace $(knscurrent) -o json | ConvertFrom-Json -AsHashtable | $_["spec"]["finalizers"]
	# & kubectl get namespace $NAMESPACE -o json |jq '.spec = {"finalizers":[]}' | ConvertFrom-Json
}

function knscurrent() {
	$Stuff = kcfg | grep \* | ForEach-Object { $_.Split(' ') }
	return $Stuff[-1]
}

function kdp { & kubectl describe pod $params }
function kci { & kubectl cluster-info }

function kga($namespace = '') {
	
	if(-not $namespace) {
		$namespace = knscurrent
	} else {

	}


	<#
NAME                                       SHORTNAMES   APIVERSION                             NAMESPACED   KIND
bindings                                                v1                                     true         Binding
configmaps                                 cm           v1                                     true         ConfigMap
endpoints                                  ep           v1                                     true         Endpoints
events                                     ev           v1                                     true         Event
limitranges                                limits       v1                                     true         LimitRange
persistentvolumeclaims                     pvc          v1                                     true         PersistentVolumeClaim
pods                                       po           v1                                     true         Pod
podtemplates                                            v1                                     true         PodTemplate
replicationcontrollers                     rc           v1                                     true         ReplicationController
resourcequotas                             quota        v1                                     true         ResourceQuota
secrets                                                 v1                                     true         Secret
serviceaccounts                            sa           v1                                     true         ServiceAccount
services                                   svc          v1                                     true         Service
challenges                                              acme.cert-manager.io/v1                true         Challenge
orders                                                  acme.cert-manager.io/v1                true         Order
controllerrevisions                                     apps/v1                                true         ControllerRevision
daemonsets                                 ds           apps/v1                                true         DaemonSet
deployments                                deploy       apps/v1                                true         Deployment
replicasets                                rs           apps/v1                                true         ReplicaSet
statefulsets                               sts          apps/v1                                true         StatefulSet
localsubjectaccessreviews                               authorization.k8s.io/v1                true         LocalSubjectAccessReview
horizontalpodautoscalers                   hpa          autoscaling/v1                         true         HorizontalPodAutoscaler
cronjobs                                   cj           batch/v1beta1                          true         CronJob
jobs                                                    batch/v1                               true         Job
apps                                                    catalog.cattle.io/v1                   true         App
operations                                              catalog.cattle.io/v1                   true         Operation
certificaterequests                        cr,crs       cert-manager.io/v1                     true         CertificateRequest
certificates                               cert,certs   cert-manager.io/v1                     true         Certificate
issuers                                                 cert-manager.io/v1                     true         Issuer
leases                                                  coordination.k8s.io/v1                 true         Lease
endpointslices                                          discovery.k8s.io/v1beta1               true         EndpointSlice
events                                     ev           events.k8s.io/v1                       true         Event
ingresses                                  ing          extensions/v1beta1                     true         Ingress
bundledeployments                                       fleet.cattle.io/v1alpha1               true         BundleDeployment
bundlenamespacemappings                                 fleet.cattle.io/v1alpha1               true         BundleNamespaceMapping
bundles                                                 fleet.cattle.io/v1alpha1               true         Bundle
clustergroups                                           fleet.cattle.io/v1alpha1               true         ClusterGroup
clusterregistrations                                    fleet.cattle.io/v1alpha1               true         ClusterRegistration
clusterregistrationtokens                               fleet.cattle.io/v1alpha1               true         ClusterRegistrationToken
clusters                                                fleet.cattle.io/v1alpha1               true         Cluster
gitreporestrictions                                     fleet.cattle.io/v1alpha1               true         GitRepoRestriction
gitrepos                                                fleet.cattle.io/v1alpha1               true         GitRepo
gitjobs                                                 gitjob.cattle.io/v1                    true         GitJob
backingimagemanagers                       lhbim        longhorn.io/v1beta1                    true         BackingImageManager
backingimages                              lhbi         longhorn.io/v1beta1                    true         BackingImage
engineimages                               lhei         longhorn.io/v1beta1                    true         EngineImage
engines                                    lhe          longhorn.io/v1beta1                    true         Engine
instancemanagers                           lhim         longhorn.io/v1beta1                    true         InstanceManager
nodes                                      lhn          longhorn.io/v1beta1                    true         Node
replicas                                   lhr          longhorn.io/v1beta1                    true         Replica
settings                                   lhs          longhorn.io/v1beta1                    true         Setting
sharemanagers                              lhsm         longhorn.io/v1beta1                    true         ShareManager
volumes                                    lhv          longhorn.io/v1beta1                    true         Volume
catalogtemplates                                        management.cattle.io/v3                true         CatalogTemplate
catalogtemplateversions                                 management.cattle.io/v3                true         CatalogTemplateVersion
cisbenchmarkversions                                    management.cattle.io/v3                true         CisBenchmarkVersion
cisconfigs                                              management.cattle.io/v3                true         CisConfig
clusteralertgroups                                      management.cattle.io/v3                true         ClusterAlertGroup
clusteralertrules                                       management.cattle.io/v3                true         ClusterAlertRule
clusteralerts                                           management.cattle.io/v3                true         ClusterAlert
clustercatalogs                                         management.cattle.io/v3                true         ClusterCatalog
clusterloggings                                         management.cattle.io/v3                true         ClusterLogging
clustermonitorgraphs                                    management.cattle.io/v3                true         ClusterMonitorGraph
clusterregistrationtokens                               management.cattle.io/v3                true         ClusterRegistrationToken
clusterroletemplatebindings                             management.cattle.io/v3                true         ClusterRoleTemplateBinding
clusterscans                                            management.cattle.io/v3                true         ClusterScan
clustertemplaterevisions                                management.cattle.io/v3                true         ClusterTemplateRevision
clustertemplates                                        management.cattle.io/v3                true         ClusterTemplate
etcdbackups                                             management.cattle.io/v3                true         EtcdBackup
globaldnses                                             management.cattle.io/v3                true         GlobalDns
globaldnsproviders                                      management.cattle.io/v3                true         GlobalDnsProvider
monitormetrics                                          management.cattle.io/v3                true         MonitorMetric
multiclusterapprevisions                                management.cattle.io/v3                true         MultiClusterAppRevision
multiclusterapps                                        management.cattle.io/v3                true         MultiClusterApp
nodepools                                               management.cattle.io/v3                true         NodePool
nodes                                                   management.cattle.io/v3                true         Node
nodetemplates                                           management.cattle.io/v3                true         NodeTemplate
notifiers                                               management.cattle.io/v3                true         Notifier
podsecuritypolicytemplateprojectbindings                management.cattle.io/v3                true         PodSecurityPolicyTemplateProjectBinding
preferences                                             management.cattle.io/v3                true         Preference
projectalertgroups                                      management.cattle.io/v3                true         ProjectAlertGroup
projectalertrules                                       management.cattle.io/v3                true         ProjectAlertRule
projectalerts                                           management.cattle.io/v3                true         ProjectAlert
projectcatalogs                                         management.cattle.io/v3                true         ProjectCatalog
projectloggings                                         management.cattle.io/v3                true         ProjectLogging
projectmonitorgraphs                                    management.cattle.io/v3                true         ProjectMonitorGraph
projectnetworkpolicies                                  management.cattle.io/v3                true         ProjectNetworkPolicy
projectroletemplatebindings                             management.cattle.io/v3                true         ProjectRoleTemplateBinding
projects                                                management.cattle.io/v3                true         Project
rkeaddons                                               management.cattle.io/v3                true         RkeAddon
rkek8sserviceoptions                                    management.cattle.io/v3                true         RkeK8sServiceOption
rkek8ssystemimages                                      management.cattle.io/v3                true         RkeK8sSystemImage
samltokens                                              management.cattle.io/v3                true         SamlToken
pods                                                    metrics.k8s.io/v1beta1                 true         PodMetrics
alertmanagerconfigs                                     monitoring.coreos.com/v1alpha1         true         AlertmanagerConfig
alertmanagers                                           monitoring.coreos.com/v1               true         Alertmanager
podmonitors                                             monitoring.coreos.com/v1               true         PodMonitor
probes                                                  monitoring.coreos.com/v1               true         Probe
prometheuses                                            monitoring.coreos.com/v1               true         Prometheus
prometheusrules                                         monitoring.coreos.com/v1               true         PrometheusRule
servicemonitors                                         monitoring.coreos.com/v1               true         ServiceMonitor
thanosrulers                                            monitoring.coreos.com/v1               true         ThanosRuler
ingresses                                  ing          networking.k8s.io/v1                   true         Ingress
networkpolicies                            netpol       networking.k8s.io/v1                   true         NetworkPolicy
poddisruptionbudgets                       pdb          policy/v1beta1                         true         PodDisruptionBudget
apprevisions                                            project.cattle.io/v3                   true         AppRevision
apps                                                    project.cattle.io/v3                   true         App
pipelineexecutions                                      project.cattle.io/v3                   true         PipelineExecution
pipelines                                               project.cattle.io/v3                   true         Pipeline
pipelinesettings                                        project.cattle.io/v3                   true         PipelineSetting
sourcecodecredentials                                   project.cattle.io/v3                   true         SourceCodeCredential
sourcecodeproviderconfigs                               project.cattle.io/v3                   true         SourceCodeProviderConfig
sourcecoderepositories                                  project.cattle.io/v3                   true         SourceCodeRepository
clusters                                                rancher.cattle.io/v1                   true         Cluster
projects                                                rancher.cattle.io/v1                   true         Project
roletemplatebindings                                    rancher.cattle.io/v1                   true         RoleTemplateBinding
rolebindings                                            rbac.authorization.k8s.io/v1           true         RoleBinding
roles                                                   rbac.authorization.k8s.io/v1           true         Role
	
# k api-resources | grep true  # tog et resources that are namespaced
#>
	
	# nodes, namespace, pv <-- cluster wide, always returned
	Write-Color -Text "Getting all resourcetypes in namespace:", $namespace -Color Gray, Green
	kubectl get "limits,quota,rc,ing,netpol,pdb,secrets,cm,cr,cert,ds,rs,sts,pvc,svc,deployment,pod,cronjob,job,events" -n $namespace


}
Set-Alias -Name kgetall kga

Set-Item -force function:kev { & kubectl get events --sort-by='.metadata.creationTimestamp' }
Set-Alias -Name kevents kev

function kgpo([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl get pods $params }
function kgpoall([Parameter(ValueFromRemainingArguments = $true)]$params) { $gg = kfind($params); $gg; } 
# & kubectl get pods --all-namespaces $params }
function kerr([Parameter(ValueFromRemainingArguments = $true)]$params) {
	#$lines = kubectl get pods --all-namespaces $params `
	#	| grep -v "Running" `
	#	| grep -v "Completed"

	$ignored = @("*Running*", "*Completed*");
	$lines = kubectl get pods --all-namespaces $params | where { $_ -notlike $ignored[0] -and $_ -notlike $ignored[1] };

	$lines = $lines | Where-Object { return (-not ($_.StartsWith("NAMESPACE"))); }
	$lines
}

Set-Item -force function:kmemdump {
	Param (
		[string]$podname,
		[string]$containername
	)

	# [string]$shell = "/bin/bash"

	Write-Host "Finding Pod";
	$pod = kfind("$podname $containername") | Where-Object { $_.Status -eq "Running" } | Select-Object -first 1;

	#$pods = kfind($searchString) 
	#$pod = $pods | Select-Object -first 1;

	if (-not $pod) {
		Write-Host "Could not find pod";
		return;
	}
	$pod.Container

	Write-Host "TODO: Ensuring Debug tools + Patching is applied";

	Write-Host "Capturing Dump from debug tools";
	# https://docs.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-dump
	# want to ensure mini dumps, not fulls are the default :p
	# /tools/dotnet-dump collect --type mini -p $(pidof dotnet) -o /tmp/dotnet.dmp

	#Write-Host "kubectl exec-as --stdin --tty $($pod.PodName) -c $($pod.Container) --namespace $($pod.Namespace) -- $shell";
	$ignored = kubectl exec --stdin --tty $($pod.PodName) -c $($pod.Container) --namespace $($pod.Namespace) -- bash -c "/tools/dotnet-dump collect --type mini -p `$(pidof dotnet) -o /tmp/dotnet.dmp"


	Write-Host "Compressing Dump file";
	#7z a /tmp/minidmp.7z /tmp/dotnet.dmp -sdel
	$ignored = kubectl exec --stdin --tty $($pod.PodName) -c $($pod.Container) --namespace $($pod.Namespace) -- bash -c "7z a /tmp/minidmp.7z /tmp/dotnet.dmp -sdel"

	Write-Host "Copying Dump file to local directory.";
	#dbapi-debuggable-6cc498f44c-lfs77
	#kubectl cp $($pod.Namespace)/$($pod.Podname):/tmp/minidmp.7z ./minidmp.7z -c $($pod.Container)
	$ignored = kubectl cp "$($pod.Namespace)/$($pod.Podname):/tmp/minidmp.7z" ./minidmp.7z -c $($pod.Container)

	if ( -not $? ) {
		$msg = $Error[0].Exception.Message;
		Write-Color -Text "$msg" -Color Red
	} 
	else {
		Write-Host "Done, minidump.7z in current folder";
	}
	
	# $($pod.Container)
	#Write-Host ">> kubectl get pods --namespace $($pod.Namespace) $($pod.Podname) -o json;"

	#return Kube-Get-Default-Port $pod
}

function kerrdelete() {

	# emulating the following:
	#kubectl get pods | grep Error | cut -d' ' -f 1 | xargs kubectl delete pod
	$lines = kerr;
	#kerr | Foreach-Object $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries) | %{ "kubectl delete pod $_[1] --namespace $_[0]" }
	$lines | ForEach-Object -Parallel { 
		$fields = (-split $_); 
		$pod = $fields[1]; 
		$ns = $fields[0]; 
		if (($ns -eq "NAMESPACE") -and ($pod -eq "NAME") ) {
			return;
		}
		$cmd = "kubectl delete pod $pod --namespace $ns"; 
		"$cmd"; 
		$ignoredOutput = Invoke-Expression $cmd 
	}
}
function kst { param ( [string[]]$ignored = @('Running', 'Completed') ) kubectl get pods --watch --all-namespaces $params | where { $_ -notmatch ('(' + [string]::Join(')|(', $ignored) + ')') }; }
function kcfg([string]$setConfig) { if (!$setConfig) { & kubectl config get-contexts } else { kubectl config use-context $setConfig } }
function knsl([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl get namespace -o wide }
function kns([string]$newNamespace, [Parameter(ValueFromRemainingArguments = $true)]$params) { 
	if ($newNamespace) { 
		"Setting namespace to $newNamespace";
		& kubectl config set-context --current --namespace=$newNamespace $params 
	}
 else { 
		& kubectl get namespace -o wide
	} 
}

Set-Item -force function:kdrain {
	Param (
		[string]$searchString
	)

	Write-Host "Draining node $searchString..";
	Write-Host ">> kubectl drain --ignore-daemonsets --delete-emptydir-data $searchString"

	& kubectl drain --ignore-daemonsets --delete-emptydir-data $searchString

	Write-Host "Node $searchString drained..";
}

Set-Item -force function:update-node {
	Param (
		[string]$searchString
	)

	Write-Color -Text '>> Draining node...' -Color Cyan
	kdrain $searchString;

	Write-Color -Text '>> Updating docker on node...' -Color Cyan
	
	Write-Color -Text '>>>> Trying ArchLinux syntax...' -Color Cyan
	& ssh root@$searchString pacman -Sy --noconfirm docker

	Write-Color -Text '>>>> Trying Ubuntu syntax...' -Color Cyan
	& ssh root@$searchString apt update `&`& apt -y --only-upgrade install docker-ce docker-ce-cli containerd.io `&`& apt -y upgrade

	Write-Color -Text '>> Restarting node...' -Color Cyan
	& ssh root@$searchString reboot

	
	Write-Color -Text '>> Waiting 10 seconds to start connection test loop..' -Color Cyan
	Start-Sleep -Seconds 10

	Write-Color -Text '>> Looping until machine responds to ssh port..' -Color Cyan
	

	do {
		Write-Color -Text '>>>> Waiting..' -Color Cyan
		Start-Sleep -Seconds 3      
	} until(Test-NetConnection $searchString -Port 22 | Where-Object { $_.TcpTestSucceeded } )

	Write-Color -Text '>> Waiting 10 seconds to give some breathing room.' -Color Cyan
	Start-Sleep -Seconds 10

	Write-Color -Text '>> Uncordoning node in kubernetes.' -Color Cyan
	kubectl uncordon $searchString;

}

Set-Item -force function:update-all-nodes {
	Param (

	)

	$nodes = @('arch2', 'drone1', 'drone3', 'drone4', 'drone5','drone6','drone7','drone8','drone9','rancher1','rancherweb')
	Write-Color -Text 'Updating nodes:' -Color Yellow
	Write-Host $array

	foreach ($node in $nodes) {
		try {
			update-node $node
		} catch  {
			#($err)
			Write-Color -Text $_.Exception -Color Red
		} finally {
			kubectl uncordon $node
		}
	}
}

function kforcepull([string]$text) {
	"Getting deployments"
	$deployment = kubectl get deployments --all-namespaces | Where-Object { $_ -like $('*' + $text + '*') } | select -first 1 # wsl grep -i $text

	"Repulling image associated with $deployment"

	#kubectl patch deployment patch-demo --patch '{"spec": {"template": {"spec": {"containers": [{"name": "patch-demo-ctr-2","image": "redis"}]}}}}'
}

function kfind([string]$text, [string]$containerName) {

	if (($text.Contains(" ")) -and ($containerName.Length -eq 0) ) {
		$parts = $text.Split(" ", [StringSplitOptions]::RemoveEmptyEntries);
		$text = $parts[0];
		$containerName = $parts[1];
	}
	Write-Host "Searching for pods in kubernetes ""$text""";

	$rows = kubectl get pods --all-namespaces | Where-Object { $_ -like $('*' + $text + '*') } # wsl grep -i $text

	foreach ($row in $rows) {
		Write-Host $row
	}
	$rv = @();

	$subContainerName = ""; # we assume all pods have the same containers, so only need to look at the first one..
	$row = $rows | Select-Object -first 1
	if ($row) {
		$pa = $row.Split(" ", [StringSplitOptions]::RemoveEmptyEntries);
		$containers = (kubectl get pod $pa[1] --namespace $pa[0] -o jsonpath='{.spec.containers[*].name}*').TrimEnd('*').Split(" ");
		if ($containers.Length -gt 1) {
			Write-Color -Text "Multiple containers found: ", $containers -Color White, Blue
			$subContainerName = $containers `
			| Sort-Object -Property Length `
			| Where-Object { $_.IndexOf($containerName, [StringComparison]::OrdinalIgnoreCase) -gt -1 } `
			| Select-Object -first 1
			Write-Color -Text "Choosing container within pod: ", $subContainerName -Color White, Yellow;
		}
	}

	foreach ($row in $rows) {
		$Obj = @{};
		$pa = $row.Split(" ", [StringSplitOptions]::RemoveEmptyEntries); 
		$Obj.Podname = $pa[1];
		$Obj.Namespace = $pa[0]; 
		$Obj.Status = $pa[3];
		if ($subContainerName) {
			$Obj.Container = $subContainerName;
		}
		$rv += (New-Object PSObject -Property $Obj)
	}
	return $rv;
}
function klf(
	[switch] $allLogs,
	[Parameter(ValueFromRemainingArguments = $true)]$podOrDeploymentName) {

	# $allLogs = $false;
	Write-Host $PSBoundParameters
	if (-not $allLogs) {
		Write-Color -Text "If you want to get ALL logs, specify ", "-all", " as a parameter" -Color White, Green, White
	}

	$pod = kfind($podOrDeploymentName) | Sort-Object -Property Status -Descending | select -first 1;
	if (-not $pod) {
		"No pod found"
		return;
	}
	"Executing into pod : $($pod.Namespace)\$($pod.Podname), [$($pod.Container))] Status: $($pod.Status)"

	if ($allLogs -eq $true) {
		Write-Color -Text "Returning ", "all", " logs since start of pod" -Color White, Green, White
		& kubectl logs --follow --tail -1 $pod.Podname $pod.Container --namespace $pod.Namespace
	}
 else {
		& kubectl logs --follow --tail 30 $pod.Podname $pod.Container --namespace $pod.Namespace
	}
}

function kte([string]$podname, [string]$containername, [string]$shell = "/bin/bash") {
	$shell = "/bin/bash"
	
	$pod = kfind("$podname $containername") | Select-Object -first 1;
	if (-not $pod ) {
		"No pod found"
		return;
	}
	Write-Color -Text "Executing into pod : ", "$($pod.Namespace)\$($pod.Podname) ", [$($pod.Container)], " Status: ", $($pod.Status), " $shell" -Color White, Yellow, Green, White, Green, Magenta

	Write-Host "exec-as and krew must be installed. https://github.com/jordanwilson230/kubectl-plugins/tree/krew#kubectl-exec-as";

	#kubectl exec -it $pod.PodName $pod.Container --namespace $pod.Namespace -- $shell
	if (-not -not $pod.Container) {
		Write-Host "kubectl exec-as --stdin --tty $($pod.PodName) -c $($pod.Container) --namespace $($pod.Namespace) -- $shell";
		kubectl exec --stdin --tty $($pod.PodName) -c $($pod.Container) --namespace $($pod.Namespace) -- $shell
	}
 else {
		Write-Host "kubectl exec-as --stdin --tty $($pod.PodName) --namespace $($pod.Namespace) -- $shell";
		kubectl exec --stdin --tty $($pod.PodName) --namespace $($pod.Namespace) -- $shell
	}
	
	
}

Set-Item -force function:Kube-Get-Default-Port-String {
	Param (
		[string]$searchString
	)

	$pod = kfind($searchString) | Select-Object -first 1;
	if (-not $pod) {
		Write-Host "Could not find pod";
		return;
	}

	# $($pod.Container)
	Write-Host ">> kubectl get pods --namespace $($pod.Namespace) $($pod.Podname) -o json;"

	return Kube-Get-Default-Port $pod
}
Set-Item -force function:Kube-Get-Default-Port {
	Param (
		[object]$pod
	)

	$js = kubectl get pod --namespace $pod.Namespace $pod.Podname -o json | ConvertFrom-Json;
	$containerSpec = $js.spec.containers | Where-Object { $_.name -eq $pod.Container } | Select-Object -first 1

	if (-not $containerSpec.ports) {
		Write-Host -ForegroundColor Red "No port information in the container spec, guessing ""80""";
		return 80;
	}
	return $containerSpec.ports[0].containerPort
}

Set-Item -force function:kpf {
	[CmdletBinding(DefaultParameterSetName = 'podcontainerport', PositionalBinding = $true, ConfirmImpact = 'Medium')]
	Param (
		#[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true,ParameterSetName='Parameter Set 1')] $p1
		[Parameter(ParameterSetName = 'podcontainerport', Mandatory = $false, Position = 0)]
		[string] $podname,

		[Parameter(ParameterSetName = 'podcontainerport', Mandatory = $false, Position = 1)]
		[string] $container,

		[Parameter(ParameterSetName = 'podcontainerport', Mandatory = $false, Position = 2)]
		[string] $port,

		[Parameter(ParameterSetName = 'podcontainerport', Mandatory = $false, Position = 3)]
		[boolean] $reconnect = $false
	)

	if (-not $podname) {
		# kpf -reconnect=$true dbapi dbapi 62160:80
		Write-Color `
			-Text "Parameters for kpf : ", "[-reconnect=`$true] ", "podname ", "[containername] ", "[local:remote] ", " `r`ne.g. `r`n", "  kpf dbapi 5000:80`r`n", `
			" or `r`n", "  kpf dbapi aws 5000:80`r`n", `
			" or `r`n", "  kpf dbapi dbapi 62160:80 `$True`r`n" `
			-Color Gray, Blue, Red, Blue, Red, Gray, Yellow, Gray, Yellow, Gray, Yellow
		return;
	}
	#[string] $podname, [string]$container, [string]$port

	if (-not $container) {
		Write-Host "No port mapping specified, choosing default container and guessing port";
	}

	if ((-not $port) -and (-not (-not $container))) {
		$port = $container
		$container = $null;
	}

	$pod = kfind -text $podname -containerName $container | Select-Object -first 1;
	
	if (-not $pod) {
		Write-Host "No pod found to port forward to. Search for podname: ""$podname""; Container: ""$container"""
		return;
	}

	if (-not $port) {
		"Port not specified, trying to guess.."
		$port = Kube-Get-Default-Port $pod

		Write-Color -Text "best guess for port is: ", $port -Color Gray, Yellow
	}

	if ($reconnect -eq $True) {
		while ($True) {
			"Looping connection...";
			">>> kubectl port-forward --namespace $($pod.Namespace) $($pod.Podname) $($pod.Container) ${port} $($containers) --address 0.0.0.0";
			& kubectl port-forward --namespace $pod.Namespace $pod.Podname $port $containers --address 0.0.0.0 #$pod.Container 
			"Reconnecting...";
			$pod = kfind -text $podname -containerName $container | Select-Object -first 1;
		}
	}
 else {
		">>> kubectl port-forward --namespace $($pod.Namespace) $($pod.Podname) $($pod.Container) ${port} $($containers) --address 0.0.0.0";
		& kubectl port-forward --namespace $pod.Namespace $pod.Podname $port $containers --address 0.0.0.0 #$pod.Container 	
	}

	

	# if($containers.Length -gt 1) {		
	# 	$containers = $containers | wsl grep $podname | select -first 1;

	# 	"Multiple containers in pod. Selected container: $containers";
		
	# } else {
	# 	"Executing << kubectl port-forward ${port} --namespace $($pod.Namespace) $($pod.Podname) >>";

	# 	& kubectl port-forward --namespace $pod.Namespace $pod.Podname $port  
	# }
	#
}
function kredeploy([Parameter(ValueFromRemainingArguments = $true)]$params) { 
	Write-Host "This is currently not functioning, the idea being to patch the imagepullpolicy briefly, force a redploy, and change it back again"
	kubectl rollout restart $params 
}
function knodepods([Parameter(ValueFromRemainingArguments = $true)]$params) { 
	"kubectl get pods --all-namespaces -o wide --field-selector spec.nodeName=$params";
	kubectl get pods --all-namespaces -o wide --field-selector spec.nodeName=$params 
}
function knp([Parameter(ValueFromRemainingArguments = $true)]$params) { knodepods $params }
function knpall([Parameter(ValueFromRemainingArguments = $true)]$params) { knodepods $params }
#endregion


#region docker alias
#https://hackernoon.com/handy-docker-aliases-4bd85089a3b8
function dkbash {
	param ( [string] $ImageId, [string] $shell = 'bash' )
	# grep $containerid = Where-Object { $_ -like $('*' + $containerId + '*') }
	# $containerId = docker ps | Where-Object { $_ -like $('*' + $containerId + '*') } | ForEach-Object { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
	
	docker run -it -e "TERM=xterm-256color" --entrypoint "/bin/${shell}" --rm ${ImageId}
}

function dkdebug {
	param ( [string] $containerId, [string] $shell = 'bash' )
	# grep $containerid = Where-Object { $_ -like $('*' + $containerId + '*') }
	$containerId = docker ps | Where-Object { $_ -like $('*' + $containerId + '*') } | ForEach-Object { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
	Write-Host "container id: $containerId";

	docker exec -it ${containerId} "sh" -c "apt install wget -y"
	docker exec -it ${containerId} "sh" -c "wget https://aka.ms/getvsdbgsh -O - 2>/dev/null | /bin/sh /dev/stdin -v vs2017u5 -l /vsdbg/vsdbg"
	docker exec -it ${containerId} "sh" -c "wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb"
	docker exec -it ${containerId} "sh" -c "dpkg -i packages-microsoft-prod.deb"
	docker exec -it ${containerId} "sh" -c "apt-get update; apt-get install -y apt-transport-https && apt-get update && apt-get install -y dotnet-sdk-3.1"
	docker exec -it ${containerId} "sh" -c "dotnet dev-certs https --clean; dotnet dev-certs https --trust"
}
function dke {
	param ( [string] $containerId, [string] $shell = 'bash' )
	# % = ForEach-Object
	#$containerId = docker ps | grep $containerId | ForEach-Object { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
	$containerId = docker ps | Where-Object { $_ -like $('*' + $containerId + '*') } | ForEach-Object { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
	
	docker exec -it ${containerId} "/bin/${shell}"
}
function dkle {
	param ( [string] $name )
	
	#$containerId = docker ps | grep $name | % { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
	$containerId = docker ps | Where-Object { $_ -like $('*' + $name + '*') } | ForEach-Object { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
	docker logs -f $containerId
	
	
	#docker logs -f `docker ps | grep $name | awk '{print $1}'`
}
#endregion

#region Helper methods
Set-Alias web "C:\src\hgr\HustleGotReal\src\Ebaylisterweb"

function portsdamnit {
	netsh int ip delete excludedportrange protocol=tcp numberofports=100 startport=1373 
	#netstat -a -b -n | rg opera
	#netstat -a -b -n | grep opera
}
function gitupdate {
	$dir = Get-GitDirectory;
	$z = $null;
	if (-not $dir) {
		Write-Color -Text "Could not locate git directory." -Color Red
		return;
	}

	$currentBranch = $(git symbolic-ref HEAD).Replace("refs/heads/", "");
	$refs = $(git for-each-ref --format='%(upstream:short)') `
		| ? { -not [string]::IsNullOrEmpty($_) }
		| % { $_.Replace("origin/", "") }

	if ($refs.Length -gt 0) {
		git fetch --all --prune
	}
	Write-Color -Text "Updating $($refs.Length) branches.." -Color Gray

	$rv = $(git stash)
	
	foreach ($br in $refs) {
		try {
			Write-Color -Text "Updating branch ", $br -Color Gray, Green
			$z = $($(git checkout $br))
			$z = $(git pull)
		}
		catch {
			Write-Color -Text "Error updating branch", $br -Color Red, White
		}
	}
	Write-Color -Text "Done pulling, returning to initial branch ", $currentBranch -Color Gray, Green

	$z = $(git checkout $currentBranch)

	if (-not $rv.StartsWith("No local changes to save")) {
		Write-Color -Text "Restoring WIP stash.." -Color Yellow
		$z = $(git stash pop)
	}
}


function gitpullall {
	if (Test-Path ".git") {
		"Updating Git repo $PWD";
		git pull --all; # pull -all does a fetch --all first..
	}
	Push-Location
	foreach ($a in $(Get-ChildItem . -Directory)) {
		Set-Location $a;
		if (Test-Path ".git") {
			"Updating Git repo at $a";
			git pull --all;
		}
		else {
			"Ignoring non git folder at $a";
		}
	}
	Pop-Location
}


function localseq { docker run --name seq -d --restart unless-stopped -e ACCEPT_EULA=Y -p 5341:80 datalust/seq:latest }

function ClearCaches {

	Write-Host "Calling other clean script (cleanpackagescache)..."
	cleanpackagescache

}
function csrc { Set-Location C:\src\mine\mpieras }
function chgr { Set-Location C:\src\hgr\HustleGotReal }
function cweb { Set-Location C:\src\hgr\HustleGotReal\src\Ebaylisterweb }
function cdocker { Set-Location c:\docker }
function cninja { Set-Location C:\src\vaninja }
function ctools { Set-Location C:\tools }
function cuserprofile { Set-Location ~ } # Helper function to set location to the User Profile directory
function rebuildall { 
	Write-Output "Deleting all bin and obj, and build/ folders";
	Get-ChildItem -recurse | ? { $_.PSIsContainer } | Where-Object { $_.Name -Like 'obj' -or $_.Name -Like 'bin' -or $_.Name -Like 'build' } | Remove-Item -Recurse -Force
	Write-Output "Deleting all project.assests.json";
	Get-ChildItem -recurse | ? { $_.Name -Like 'project.assets.json' } | Remove-Item -Recurse -Force
	
	Write-Output "Restoring Nugets..";
	nuget restore
	
	Write-Output "MsBuild clean..";
	msbuild /t:clean /p:Configuration="Release" /verbosity:minimal
	
	Write-Output "MsBuild restore..";
	msbuild /t:restore /p:Configuration="Release" /verbosity:minimal
	
	Write-Output "msbuild build.."
	msbuild /p:Configuration="Release" /verbosity:Minimal
}



Set-Item -force function:Update-Profile-In-Git {
	Push-Location
	Set-Location $profilePath
	git add .
	git commit -m "Updated profile";
	git push
	Pop-Location
}
Set-Alias saveProfile Update-Profile-In-Git
Set-Alias commitProfile Update-Profile-In-Git


Set-Item -force function:installTools {
	if (-not (Test-CommandExists scoop)) {
		Write-Host "Installing scoop.";
		Set-ExecutionPolicy RemoteSigned -scope CurrentUser
		Invoke-Expression (new-object net.webclient).downloadstring('https://get.scoop.sh')
		scoop bucket add extras

		Write-Host "Known scoop buckets:"
		scoop bucket known
	}

	if (-not (Test-CommandExists choco)) {
		Write-Host "Installing chocolatey.";
		Set-ExecutionPolicy RemoteSigned -scope CurrentUser
		Set-ExecutionPolicy Bypass -Scope Process -Force
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
		Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	}

	
	scoop install sysinternals 7zip git helm kubectl nano powertoys oh-my-posh3 spacesniffer golang

	if(-not $devTools) {
		Write-Host "not installing additional dev tools."
	} else {
		Write-Host "Installing additional dev tools."
		scoop install go
	}

}


# if (Test-CommandExists Reload-Profile) {
# 	Write-Host -ForegroundColor Magenta "Reload-profile exists, removing.."
# 	Remove-Item function:Reload-Profile -force; 
# 	Start-Sleep 1;
# }

Set-Item -force function:Reload-Profile {
	$hs = New-Object 'System.Collections.Generic.HashSet[string]' # hashset so we don't load the same profile multiple times

	@(
		$Profile.AllUsersAllHosts,
		$Profile.AllUsersCurrentHost,
		$Profile.CurrentUserAllHosts,
		$Profile.CurrentUserCurrentHost,
		$Profile
	) | ForEach-Object {
		
		if ((Test-Path $_) -and (-Not $hs.Contains($_))) {
			$nope = $hs.Add($_)
			#Write-Host -ForegroundColor Green $_ 
			
			#Write-Verbose "Running $_"
			$measure = Measure-Command { . $_ }
			Write-Color -Text "$($measure.TotalMilliSeconds)", " for ", "$_" -Color Blue, White, Yellow
			#$(. $_)
		}
		else {
			#Write-Host -ForegroundColor Red $_ 
		}
	}

	#& "C:\ProgramData\chocolatey\bin\RefreshEnv.cmd"
	# Update-SessionEnvironment is defined in chocolatey

	if (Test-CommandExists refreshenv) {
		refreshenv; #Update-SessionEnvironment
	}
 else {
		Write-Host -ForegroundColor Red "Could not call refreshenv, is chocolatey installed? Run 'iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))' to install if not..";
	}
	
	Write-Host "Reloaded Profile(s)";
	# . $profile;
}



Set-Alias refreshps Reload-Profile
Set-Alias reload Reload-Profile
#endregion

# Set l and ls alias to use the new Get-ChildItemColor cmdlets
Set-Alias l Get-ChildItemColor -Option AllScope
Set-Alias ls Get-ChildItemColorFormatWide -Option AllScope


function cleanall {
	Push-Location
	Write-Output "Deleting all bin, obj, packages and build/ folders";
	Get-ChildItem -recurse | Where-Object { $_.PSIsContainer } | Where-Object { $_.Name -Like 'obj' -or $_.Name -Like 'packages' -or $_.Name -Like 'bin' -or $_.Name -Like 'build' } | Remove-Item -Recurse -Force
	Write-Output "Deleting all project.assets.json";
	Get-ChildItem -recurse | Where-Object { $_.Name -Like 'project.assets.json' } | Remove-Item -Recurse -Force
	Pop-Location
}



# $PSScriptRoot\Microsoft.PowerShell_profile.ps1 
Write-Color -Text "Profile loaded from ", $profile -Color Gray, Green
if ($isAdmin) {
	Write-Color -Text "** Administrator mode ", "ON ", "**" -Color Gray, Green, Gray
}
else {
	$txts = @("** Administrator mode ", "OFF ", "** - run ","gosudo",", ","elevate"," or ","GoAdmin"," to open")
	Write-Color -Text $txts -Color Gray, Red, Gray, Magenta, Gray, Magenta, Gray, Magenta, Gray
}

# Import-Module posh-dotnet

Import-Module DockerCompletion

# Import-Module npm-completion

Import-Module scoop-completion

Import-Module yarn-completion


# oh-my-posh V3, custom theme
Set-PoshPrompt -Theme "$scriptPath\ohmyposhtheme.json"

$Texts = @("Setting theme to ", `
"$scriptPath\ohmyposhtheme.json", `
". If file does not exist, run `"", `
 "Write-PoshTheme | Out-File -FilePath ""$scriptPath\ohmyposhtheme.json"" -Encoding oem", 
"`" to generate it. `nDocumentation at ", `
 "https://ohmyposh.dev/docs/configure/", "`r`nRun ", "DoUpdates", " to update everything, and to cleanup space, run ", "cleanpackagescache")

Write-Color -Text $Texts -Color White, Green, White, DarkGray, White, Blue, White, Magenta, White, Magenta

