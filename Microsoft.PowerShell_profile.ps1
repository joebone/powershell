#region Imports / other files
# loader.psm1
function InstallModuleIfAbsent {
	param([string]$name)
	if (-not(Get-Module -ListAvailable -Name $name)) {
		Write-Host "  Module $name is absent > Install to current user.  " -ForegroundColor Black -BackgroundColor Yellow
		Install-Module $name -Scope CurrentUser -Force -AllowClobber
	}
}
#Export-ModuleMember -Function InstallModuleIfAbsent
########################################
#endregion

# $env:Path += ";C:\tools\cygwin\bin\"

if(-not (Test-CommandExists rg)) {
	Write-Color -Text "ripgrep not detected, run ","choco install ripgrep" -Color White,Red
} else {
	Write-Color -Text "Aliasing ", "grep ","to ","rg"," - ripgrep ftw (pipeline and inline mode supported)!" -Color White, Green, White, Green, White

	Set-Item function:grep -force { 
		[CmdletBinding(DefaultParameterSetName='paramonly',PositionalBinding=$true,ConfirmImpact='Medium')]
		Param (
			#[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true,ParameterSetName='Parameter Set 1')] $p1
			[Parameter(ParameterSetName='paramonly',Mandatory=$true,Position = 0)] 
			[Parameter(ParameterSetName='pipeparam',Mandatory=$true,Position = 0)]
			[string[]] $searchString,

			[Parameter(ParameterSetName='pipeparam',Mandatory=$true,ValueFromPipeline=$true)] 
			[Parameter(ParameterSetName='pipeonly',Mandatory=$true,ValueFromPipeline=$true)]
			[string[]] $pipeline
		)
		Process {
			if($pipeline) {
				$pipeline | rg -i $searchString
			} else {
				rg -i $searchString 
			}
		}
	}
}

function Mem-Hogs { get-process | ? {($_.PM -gt 10000000) -or ($_.VM -gt 10000000)} }
Set-Alias free Mem-Hogs

#region Profile imports
InstallModuleIfAbsent -name ProductivityTools.PSTestCommandExists
InstallModuleIfAbsent -name PSWriteColor
InstallModuleIfAbsent -name posh-git
# Import-Module Telnet # https://www.techtutsonline.com/powershell-alternative-telnet-command/

#https://github.com/JanDeDobbeleer/oh-my-posh
InstallModuleIfAbsent -name oh-my-posh
Set-Theme Paradox # Darkblood | Agnoster | Paradox


#region PSReadline Options
######################################################################## PSReadLine Options
InstallModuleIfAbsent -name PSReadLine
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
#Set-Alias -Name k -Value kubectl
#endregion

#region kubectl aliases
function k([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl $params }
function kg([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl get -o wide $params }
function kde([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl describe $params }
function kgpo([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl get pods $params }
function kgpoall([Parameter(ValueFromRemainingArguments = $true)]$params) { $gg=kfind($params); $gg; } 
# & kubectl get pods --all-namespaces $params }
function kerr([Parameter(ValueFromRemainingArguments = $true)]$params) {
	#$lines = kubectl get pods --all-namespaces $params `
	#	| grep -v "Running" `
	#	| grep -v "Completed"

	$ignored = @("*Running*", "*Completed*");
	$lines = kubectl get pods --all-namespaces $params | where { $_ -notlike $ignored[0] -and $_ -notlike $ignored[1] };

	$lines
}

function kerrdelete() {

	# emulating the following:
	#kubectl get pods | grep Error | cut -d' ' -f 1 | xargs kubectl delete pod
	$lines = kerr;

	#kerr | Foreach-Object $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries) | %{ "kubectl delete pod $_[1] --namespace $_[0]" }
	kerr | % { $fields = (-split $_); $pod=$fields[1]; $ns=$fields[0]; $cmd = "kubectl delete pod $pod --namespace $ns"; "$cmd"; $_ = Invoke-Expression $cmd }

}
function kst { param ( [string[]]$ignored = @('Running', 'Completed') ) kubectl get pods --watch --all-namespaces $params | where { $_ -notmatch ('(' + [string]::Join(')|(', $ignored) + ')') }; }
function kcfg([string]$setConfig) { if (!$setConfig) { & kubectl config get-contexts } else { kubectl config use-context $setConfig } }
function knsl([Parameter(ValueFromRemainingArguments = $true)]$params) { & kubectl get namespace -o wide }
function kns([string]$newNamespace, [Parameter(ValueFromRemainingArguments = $true)]$params) { 
	if ($newNamespace) { 
		"Setting namespace to $newNamespace";
		& kubectl config set-context --current --namespace=$newNamespace $params 
	} else { 
		& kubectl get namespace -o wide
	} 
}

function kforcepull([string]$text) {
	"Getting deployments"
	$deployment = kubectl get deployments --all-namespaces | Where-Object { $_ -like $('*' + $text + '*') } | select -first 1 # wsl grep -i $text

	"Repulling image associated with $deployment"

	#kubectl patch deployment patch-demo --patch '{"spec": {"template": {"spec": {"containers": [{"name": "patch-demo-ctr-2","image": "redis"}]}}}}'
}

function kfind([string]$text, [string]$containerName) {

	if(($text.Contains(" ")) -and ($containerName.Length -eq 0) ) {
		$parts = $text.Split(" ", [StringSplitOptions]::RemoveEmptyEntries);
		$text = $parts[0];
		$containerName = $parts[1];
	}
	Write-Host "Searching for pods in kubernetes ""$text""";

	$rows = kubectl get pods --all-namespaces | Where-Object { $_ -like $('*' + $text + '*') } # wsl grep -i $text

	foreach($row in $rows){
		Write-Host $row
	}
	$rv = @();

	$subContainerName = ""; # we assume all pods have the same containers, so only need to look at the first one..
	$row = $rows | Select-Object -first 1
	if($row) {
		$pa = $row.Split(" ", [StringSplitOptions]::RemoveEmptyEntries);
		$containers = (kubectl get pod $pa[1] --namespace $pa[0] -o jsonpath='{.spec.containers[*].name}*').TrimEnd('*').Split(" ");
		if($containers.Length -gt 1) {
			Write-Color -Text "Multiple containers found: ",$containers -Color White,Blue
			$subContainerName = $containers `
					| Sort-Object -Property Length `
					| Where-Object { $_.IndexOf($containerName, [StringComparison]::OrdinalIgnoreCase) -gt -1 } `
					| Select-Object -first 1
			Write-Color -Text "Choosing container within pod: ", $subContainerName -Color White,Yellow;
		}
	}

	foreach($row in $rows) {
		$Obj = @{};
		$pa = $row.Split(" ", [StringSplitOptions]::RemoveEmptyEntries); 
		$Obj.Podname = $pa[1];
		$Obj.Namespace = $pa[0]; 
		$Obj.Status = $pa[3];
		if($subContainerName) {
			$Obj.Container = $subContainerName;
		}
		$rv += (New-Object PSObject -Property $Obj)
	}
	return $rv;
}
function klf([Parameter(ValueFromRemainingArguments = $true)]$podOrDeploymentName) {

	$pod = kfind($podOrDeploymentName) | Sort-Object -Property Status -Descending | select -first 1;
	if(-not $pod) {
		"No pod found"
		return;
	}
	"Executing into pod : $($pod.Namespace)\$($pod.Podname), [$($pod.Container))] Status: $($pod.Status)"

	& kubectl logs --follow --tail 30 $pod.Podname $pod.Container --namespace $pod.Namespace
}

function kte([string]$podname, [string]$containername, [string]$shell = "/bin/bash") {
	
	$pod = kfind("$podname $containername") | Where-Object { $_.Status -eq "Running" } | Select-Object -first 1;
	if(-not $pod -or -not $pod.Container ) {
		"No pod or specific container found"
		return;
	}
	Write-Color -Text "Executing into pod : ","$($pod.Namespace)\$($pod.Podname) ",[$($pod.Container)]," Status: ", $($pod.Status), " $shell" -Color White, Yellow, Green, White, Green, Magenta

	#kubectl exec -it $pod.PodName $pod.Container --namespace $pod.Namespace -- $shell
	Write-Host "kubectl exec --stdin --tty $($pod.PodName) -c $($pod.Container) --namespace $($pod.Namespace) -- $shell";
	kubectl exec --stdin --tty $($pod.PodName) -c $($pod.Container) --namespace $($pod.Namespace) -- $shell
}

Set-Item -force function:Kube-Get-Default-Port-String {
	Param (
		[string]$searchString
	)

	$pod = kfind($searchString) | Select-Object -first 1;
	if(-not $pod) {
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

	return $containerSpec.ports[0].containerPort
}

Set-Item -force function:kpf {
	[CmdletBinding(DefaultParameterSetName='podcontainerport',PositionalBinding=$true,ConfirmImpact='Medium')]
	Param (
			#[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true,ParameterSetName='Parameter Set 1')] $p1
			[Parameter(ParameterSetName='podcontainerport',Mandatory=$false,Position = 0)]
			[string] $podname,

			[Parameter(ParameterSetName='podcontainerport',Mandatory=$false,Position = 1)]
			[string] $container,

			[Parameter(ParameterSetName='podcontainerport',Mandatory=$false,Position = 2)]
			[string] $port
		)

	if (-not $podname) {
		Write-Color `
			-Text "Parameters for kpf : ","podname ","[containername] ","[local:remote] ", " `r`ne.g. `r`n", "  kpf dbapi 5000:80`r`n", `
				  " or `r`n","  kpf dbapi aws 5000:80`r`n" `
			-Color Gray,Red,Blue,Red,Gray,Yellow,Gray,Yellow
		return;
	}
	#[string] $podname, [string]$container, [string]$port

	if(-not $container) {
		Write-Host "No port mapping specified, choosing default container and guessing port";
	}

	if ((-not $port) -and (-not (-not $container))) {
		$port = $container
		$container = $null;
	}

	$pod = kfind -text $podname -containerName $container | Select-Object -first 1;
	
	if(-not $pod) {
		Write-Host "No pod found to port forward to. Search for podname: ""$podname""; Container: ""$container"""
		return;
	}

	if(-not $port) {
		"Port not specified, trying to guess.."
		$port = Kube-Get-Default-Port $pod

		Write-Color -Text "best guess for port is: ", $port -Color Gray, Yellow
	}

	">>> kubectl port-forward --namespace $($pod.Namespace) $($pod.Podname) $($pod.Container) ${port} $($containers) --address 0.0.0.0";
	& kubectl port-forward --namespace $pod.Namespace $pod.Podname $port $containers --address 0.0.0.0 #$pod.Container 

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
	$containerId = docker ps | Where-Object { $_ -like $('*' + $containerId + '*') } | ForEach-Object { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
	
	docker run -it --entrypoint "/bin/${shell}" --rm ${ImageId}
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
	$containerId = docker ps | Where-Object { $_ -like $('*' + $name + '*') } | % { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
	docker logs -f $containerId
	
	
	#docker logs -f `docker ps | grep $name | awk '{print $1}'`
}
#endregion

#region Helper methods
Set-Alias web "C:\src\hgr\HustleGotReal\src\Ebaylisterweb"

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
		} else {
			"Ignoring non git folder at $a";
		}
	}
	Pop-Location
}


function localseq { docker run --name seq -d --restart unless-stopped -e ACCEPT_EULA=Y -p 5341:80 datalust/seq:latest }


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





# if (Test-CommandExists Reload-Profile) {
# 	Write-Host -ForegroundColor Magenta "Reload-profile exists, removing.."
# 	Remove-Item function:Reload-Profile -force; 
# 	Start-Sleep 1;
# }

Set-Item function:Reload-Profile {
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
			Write-Color -Text "$($measure.TotalMilliSeconds)"," for ","$_" -Color Blue,White,Yellow
			#$(. $_)
		} else {
			#Write-Host -ForegroundColor Red $_ 
		}
	}

	#& "C:\ProgramData\chocolatey\bin\RefreshEnv.cmd"
	# Update-SessionEnvironment is defined in chocolatey

	if (Test-CommandExists refreshenv) {
		refreshenv; #Update-SessionEnvironment
	} else {
		Write-Host -ForegroundColor Red "Could not call refreshenv, is chocolatey installed? Run 'iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))' to install if not..";
	}
	
	Write-Host "Reloaded Profile(s)";
	# . $profile;
} -force



Set-Alias refreshps Reload-Profile
Set-Alias reload Reload-Profile
#endregion

# Set l and ls alias to use the new Get-ChildItemColor cmdlets
Set-Alias l Get-ChildItemColor -Option AllScope
Set-Alias ls Get-ChildItemColorFormatWide -Option AllScope


function cleanall {
	echo "Deleting all bin, obj, packages and build/ folders";
	Get-ChildItem -recurse | ? { $_.PSIsContainer } | Where-Object { $_.Name -Like 'obj' -or $_.Name -Like 'packages' -or $_.Name -Like 'bin' -or $_.Name -Like 'build' } | Remove-Item -Recurse -Force
	echo "Deleting all project.assets.json";
	Get-ChildItem -recurse | ? { $_.Name -Like 'project.assets.json' } | Remove-Item -Recurse -Force
}

Write-Host -ForegroundColor Green "Profile loaded from $profile." # $PSScriptRoot\Microsoft.PowerShell_profile.ps1 