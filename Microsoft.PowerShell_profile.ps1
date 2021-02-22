#region Imports / other files
# loader.psm1

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$DefaultUser = 'Joe@JOEBONE-LAPTOP'
$hosts = "C:\Windows\System32\drivers\etc\hosts"
$appdata = "$HOME/appdata/local"
$temp = "$HOME/appdata/local/temp"
$tmp = "$HOME/appdata/local/temp"

function InstallModuleIfAbsent {
	param(
		[string]$name, 
		[Parameter(Mandatory = $false)][switch]$PreRelease = $false)
	if (-not(Get-Module -ListAvailable -Name $name)) {
		Write-Host "  Module $name is absent > Install to current user.  " -ForegroundColor Black -BackgroundColor Yellow
		if ($PreRelease) {
			Install-Module $name -Scope CurrentUser -Force -AllowClobber -AllowPrerelease
		}
		else {
			Install-Module $name -Scope CurrentUser -Force -AllowClobber
		}
	}
	Import-Module $name
}
function GoAdmin { 
	if ($isAdmin) { Write-Host "Already in admin mode"; return ; }
	& Start-Process wt "/d . pwsh" –Verb RunAs; exit;
}
Set-Alias elevate GoAdmin
Set-Alias sudo GoAdmin

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
$env:Path = "$(Resolve-Path ~)\.krew\bin;" + $env:Path; # after installing krew (https://github.com/kubernetes-sigs/krew/releases)

if (-not (Test-CommandExists node)) {
	Write-Color -Text "" -Color White;
	$vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Preview\MSBuild\Microsoft\VisualStudio\NodeJs"
	if (Test-Path $vsPath) {
		$env:Path += ";$vsPath";
		Write-Color -Text "", "Nodejs not detected ", " in path. Adding VS path to environment:", $vsPath -Color White, Red, White, Green;
	}
}

if (-not (Test-CommandExists rg)) {
	Write-Color -Text "ripgrep not detected, run ", "choco install ripgrep" -Color White, Red
}
else {
	Write-Color -Text "Aliasing ", "grep ", "to ", "rg", " - ripgrep ftw (pipeline and inline mode supported)!" -Color White, Green, White, Green, White

	Set-Alias grep rg
	# Set-Item -force function:grep { 
	# 	[CmdletBinding(DefaultParameterSetName='paramonly',PositionalBinding=$true,ConfirmImpact='Medium')]
	# 	Param (
	# 		#[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true,ParameterSetName='Parameter Set 1')] $p1
	# 		[Parameter(ParameterSetName='paramonly', Mandatory=$true, Position = 0)] 
	# 		[Parameter(ParameterSetName='pipeparam', Mandatory=$true, Position = 0)]
	# 		[string[]] $searchString,

	# 		[Parameter(ParameterSetName='pipeparam', Mandatory=$true, ValueFromPipeline=$true)] 
	# 		[Parameter(ParameterSetName='pipeonly',  Mandatory=$true, ValueFromPipeline=$true)]
	# 		[AllowEmptyString()] [string] $pipeline
	# 	)
	# 	Begin {
	# 		Write-Host "Search string: $searchString, Pipeline Length : $($pipeline.length) : pipeline? $(-not (-not $pipeline))";
	# 	}
	# 	Process {

	# 		#Write-Host "b4 :  $($pipeline.Length) $($pipeline.Substring(0, 3))"
	# 		if($pipeline) {
	# 			#Write-Host "pp"
	# 			#Write-Host $pipeline.Substring(0, 10)
	# 			#netstat -a -b -n | rg --context 1 -S opera
	# 			#$pipeline = $pipeline | ? { (-not (-not $_)) } | % { if(-not $_) { return; } } 
	# 			Write-Host "$pipeline | rg --context 2 -i $searchString";
	# 			$pipeline | rg --context 2 -i $searchString
	# 		} else {
	# 			return;
	# 			rg --context 1 -S $searchString 
	# 		}
	# 	}
	# }
}


# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_format.ps1xml?view=powershell-7.1&viewFallbackFrom=powershell-6
InstallModuleIfAbsent -name Terminal-Icons

function Mem-Hogs { get-process | ? { ($_.PM -gt 10000000) -or ($_.VM -gt 10000000) } }
Set-Alias free Mem-Hogs

#region Profile imports
InstallModuleIfAbsent -name ProductivityTools.PSTestCommandExists
InstallModuleIfAbsent -name PSWriteColor
InstallModuleIfAbsent -name posh-git
# Import-Module Telnet # https://www.techtutsonline.com/powershell-alternative-telnet-command/

#https://github.com/JanDeDobbeleer/oh-my-posh
InstallModuleIfAbsent -name oh-my-posh -PreRelease
InstallModuleIfAbsent -name PSKubectlCompletion

# Set-Theme Paradox # Darkblood | Agnoster | Paradox

# oh-my-posh V3, custom theme
Set-PoshPrompt -Theme  ~/.oh-my-posh.json
Write-Color -Text "Setting theme to ", "~/.oh-my-posh.json", ". If file does not exist, run `"", `
	"Write-PoshTheme | Out-File -FilePath ~/.go-my-posh.json -Encoding oem", "`" to generate it. `nDocumentation at ", `
	"https://ohmyposh.dev/docs/configure/" `
	-Color White, Green, White, DarkGray, White, Blue
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
	$containerId = docker ps | Where-Object { $_ -like $('*' + $name + '*') } | % { $_.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0] }
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
		}
	}
	Write-Color -Text "Done pulling, returning to initial branch ", $currentBranch -Color Gray, Green

	$z = $(git checkout $currentBranch)

	if (-not $rv.StartsWith("No local changes to save")) {
		Write-Color -Text "Restoring WIP stash..", -Color Yellow
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
	nuget locals all -Clear # all nugets
	npm cache clean -force # npm folders
	yarn cache clean -force # yarn...
	C:\ProgramData\chocolatey\bin\choco-cleaner.bat # chocolatey caches..

	# temp folder
	pushd
	cd $env:TEMP 
	gci | rm -Recurse -Force
	popd

	# Clear WSL space, compact the vhds?
	wsl.exe --list --verbose
	#wsl --terminate <DistributionName>
	wsl --shutdown 
	# $pathToVHD = $("$Env:LOCALAPPDATA\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc")

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
	Write-Color -Text "** Administrator mode ", "OFF ", "** - run sudo, elevate or GoAdmin to open" -Color Gray, Red, Gray
}
