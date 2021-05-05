###########################################################################################
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

using namespace System.Management.Automation.
using namespace System.Management.Automation.Runspaces

Set-StrictMode -Version latest

###########################################################################################
# A list of modules native to PowerShell Core that should never be imported
$NeverImportList = @(
    "PSReadLine",
    "PackageManagement",
    "PowerShellGet",
    "Microsoft.PowerShell.Archive",
    "Microsoft.PowerShell.Host",
    "WindowsCompatibility"
)

###########################################################################################
# The following is a list of modules native to PowerShell Core that don't have all of
# the functionality of Windows PowerShell 5.1 versions. These modules can be imported but
# will not overwrite any existing PowerShell Core commands
$NeverClobberList = @(
    "Microsoft.PowerShell.Management",
    "Microsoft.PowerShell.Utility",
    "Microsoft.PowerShell.Security",
    "Microsoft.PowerShell.Diagnostics"
)

###########################################################################################
# A list of compatibile modules that exist in Windows PowerShell that aren't available
# to PowerShell Core by default. These modules, along with CIM modules can be installed
# in the PowerShell Core module repository using the Copy-WinModule command.
$CompatibleModules = @(
    "AppBackgroundTask",
    "AppLocker",
    "Appx",
    "AssignedAccess",
    "BitLocker",
    "BranchCache",
    "CimCmdlets",
    "ConfigCI",
    "Defender",
    "DeliveryOptimization",
    "DFSN",
    "DFSR",
    "DirectAccessClientComponents",
    "Dism",
    "EventTracingManagement",
    "GroupPolicy",
    "Hyper-V",
    "International",
    "IscsiTarget",
    "Kds",
    "MMAgent",
    "MsDtc",
    "NetAdapter",
    "NetConnection",
    "NetSecurity",
    "NetTCPIP",
    "NetworkConnectivityStatus",
    "NetworkControllerDiagnostics",
    "NetworkLoadBalancingClusters",
    "NetworkSwitchManager",
    "NetworkTransition",
    "PKI",
    "PnpDevice",
    "PrintManagement",
    "ProcessMitigations",
    "Provisioning",
    "PSScheduledJob",
    "ScheduledTasks",
    "SecureBoot",
    "SmbShare",
    "Storage",
    "TrustedPlatformModule",
    "VpnClient",
    "Wdac",
    "WindowsDeveloperLicense",
    "WindowsErrorReporting",
    "WindowsSearch",
    "WindowsUpdate"
)

# Module-scope variable to hold the active compatibility session name
$SessionName = $null

# The computer name to use if one isn't provided.
$SessionComputerName = 'localhost'

# Specifies the default configuration to connect to when creating the compatibility session
$SessionConfigurationName = 'Microsoft.PowerShell'

Set-Alias -Name Add-WinPSModulePath -Value Add-WindowsPSModulePath

# Location Changed handler that keeps the compatibility session PWD in sync with the parent PWD
# This only applies on localhost.
$locationChangedHandler = {
    [PSSession] $session = Initialize-WinSession -ComputerName $SessionComputerName -ConfigurationName $SessionConfigurationName -PassThru
    if ($session.ComputerName -eq "localhost")
    {
        $newPath = $_.newPath
        Invoke-Command -Session $session { Set-Location $using:newPath}
    }
}

$ExecutionContext.InvokeCommand.LocationChangedAction = $locationChangedHandler

# Remove the location changed handler if the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    if ($ExecutionContext.InvokeCommand.LocationChangedAction -eq $locationChangedHandler)
    {
        $ExecutionContext.InvokeCommand.LocationChangedAction = $null
    }
}

function Initialize-WinSession
{
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    Param (

        # If you don't want to use the default compatibility session, use
        # this parameter to specify the name of the computer on which to create
        # the compatibility session.
        [Parameter(Mandatory=$false,Position=0)]
        [String]
        [Alias("Cn")]
            $ComputerName,

        # Specifies the configuration to connect to when creating the compatibility session
        # (Defaults to 'Microsoft.PowerShell')
        [Parameter()]
        [String]
            $ConfigurationName,

        # The credential to use when connecting to the target machine/configuration
        [Parameter()]
        [PSCredential]
            $Credential,

        # If present, the specified session object will be returned
        [Parameter()]
        [Switch]
            $PassThru
    )

    [bool] $verboseFlag = $PSBoundParameters['Verbose']

    if ($ComputerName -eq ".")
    {
        $ComputerName = "localhost"
    }

    Write-Verbose -Verbose:$verboseFlag "Initializing the compatibility session on host '$ComputerName'."

    if ($ComputerName)
    {
        $script:SessionComputerName = $ComputerName
    }
    else
    {
        $ComputerName = $script:SessionComputerName
    }

    if ($ConfigurationName)
    {
        $script:SessionConfigurationName = $ConfigurationName
    }
    else
    {
        $ConfigurationName = $script:SessionConfigurationName
    }

    if ($Credential)
    {
        $script:SessionName = "wincompat-$ComputerName-$($Credential.UserName)"
    }
    else
    {
        $script:SessionName = "wincompat-$ComputerName-$([environment]::UserName)"
    }

    Write-Verbose -Verbose:$verboseFlag "The compatibility session name is '$script:SessionName'."

    $session = Get-PSSession | Where-Object {
        $_.ComputerName      -eq $ComputerName -and
        $_.ConfigurationName -eq $ConfigurationName -and
        $_.Name              -eq $script:SessionName
        } | Select-Object -First 1

    # Deal with the possibilities of multiple sessions. This might arise
    # from the user hitting ctrl-C. We'll make the assumption that the
    # first one returned is the correct one and we'll remove the rest.
    $session, $rest = $session
    if ($rest)
    {
        foreach ($s in $rest)
        {
            Remove-PSSession  $s
        }
    }

    if ($session -and $session.State -ne "Opened")
    {
        Write-Verbose -Verbose:$verboseFlag "Removing closed compatibility session."
        Remove-PSSession $session
        $session = $null
    }

    if (-not $session)
    {
        $newPSSessionParameters = @{
            Verbose           = $verboseFlag
            ComputerName      = $ComputerName
            Name              = $script:sessionName
            ConfigurationName = $configurationName
            ErrorAction       = "Stop"
        }
        if ($Credential)
        {
            $newPSSessionParameters.Credential = $Credential
        }
        if ($ComputerName -eq "localhost" -or $ComputerName -eq [environment]::MachineName)
        {
            $newPSSessionParameters.EnableNetworkAccess = $true
        }

        Write-Verbose -Verbose:$verboseFlag "Created new compatibiilty session on host '$computername'"
        $session = New-PSSession @newPSSessionParameters | Select-Object -First 1
        if ($session.ComputerName -eq "localhost")
        {
            $usingPath = (Get-Location).Path
            Invoke-Command $session { Set-Location $using:usingPath }
        }
    }
    else
    {
        Write-Verbose -Verbose:$verboseFlag "Reusing the existing compatibility session; 'host = $script:SessionComputerName'."
    }

    if ($PassThru)
    {
        return $session
    }
}

function Add-WinFunction
{
    [CmdletBinding()]
    [OutputType([void])]
    Param
    (
        # The name of the function to define
        [Parameter(Mandatory,Position=0)]
        [String]
        [Alias("FunctionName")]
            $Name,

        # Scriptblock to use as the body of the function
        [Parameter(Mandatory,Position=1)]
        [ScriptBlock]
            $ScriptBlock,

        # If you don't want to use the default compatibility session, use
        # this parameter to specify the name of the computer on which to create
        # the compatibility session.
        [Parameter()]
        [String]
        [Alias("Cn")]
            $ComputerName,

        # Specifies the configuration to connect to when creating the compatibility session
        # (Defaults to 'Microsoft.PowerShell')
        [Parameter()]
        [String]
            $ConfigurationName,

        # The credential to use when creating the compatibility session
        # using the target machine/configuration
        [Parameter()]
        [PSCredential]
            $Credential
    )
    # Make sure the session is initialized
    [void] $PSBoundParameters.Remove('Name')
    [void] $PSBoundParameters.Remove('ScriptBlock')

    # the session variable will be captured in the closure
    $session = Initialize-WinSession @PSBoundParameters -PassThru
    $wrapper = {
        Invoke-Command -Session $session -Scriptblock $ScriptBlock -ArgumentList $args
    }
    Set-item function:Global:$Name $wrapper.GetNewClosure();
}

function Invoke-WinCommand
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        # The scriptblock to invoke in the compatibility session
        [Parameter(Mandatory, Position=0)]
        [ScriptBlock]
            $ScriptBlock,

        # If you don't want to use the default compatibility session, use
        # this parameter to specify the name of the computer on which to create
        # the compatibility session.
        [Parameter()]
        [String]
        [Alias("cn")]
            $ComputerName,

        # Specifies the configuration to connect to when creating the compatibility session
        # (Defaults to 'Microsoft.PowerShell')
        [Parameter()]
        [String]
            $ConfigurationName,

        # The credential to use when connecting to the compatibility session.
        [Parameter()]
        [PSCredential]
            $Credential,

        # Arguments to pass to the scriptblock
        [Parameter(ValueFromRemainingArguments)]
        [object[]]
            $ArgumentList
    )

    [void] $PSBoundParameters.Remove('ScriptBlock')
    [void] $PSBoundParameters.Remove('ArgumentList')

    # Make sure the session is initialized
    [PSSession] $session = Initialize-WinSession @PSBoundParameters -PassThru

    # And invoke the scriptblock in the session
    Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function Get-WinModule
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        # Pattern to filter module names by
        [Parameter(Mandatory=$false, Position=0)]
        [String[]]
            $Name='*',

        # If you don't want to use the default compatibility session, use
        # this parameter to specify the name of the computer on which to create
        # the compatibility session.
        [Alias("cn")]
        [String]
            $ComputerName,

        # Specifies the configuration to connect to when creating the compatibility session
        # (Defaults to 'Microsoft.PowerShell')
        [Parameter()]
        [String]
            $ConfigurationName,

        # The credential to use when creating the compatibility session
        # using the target machine/configuration
        [Parameter()]
        [PSCredential]
            $Credential,

        # If specified, the complete deserialized module object
        # will be returned instead of the abbreviated form returned
        # by default.
        [Parameter()]
        [Switch]
            $Full
    )

    [bool] $verboseFlag = $PSBoundParameters['Verbose']

    Write-Verbose -Verbose:$verboseFlag 'Connecting to compatibility session.'
    $initializeWinSessionParameters = @{
        Verbose           = $verboseFlag
        ComputerName      = $ComputerName
        ConfigurationName = $ConfigurationName
        Credential        = $Credential
        PassThru          = $true
    }
    [PSSession] $session = Initialize-WinSession @initializeWinSessionParameters

    if ($name -ne '*')
    {
        Write-Verbose -Verbose:$verboseFlag "Getting the list of available modules matching '$name'."
    }
    else
    {
        Write-Verbose -Verbose:$verboseFlag 'Getting the list of available modules.'
    }

    $propertiesToReturn = if ($Full) { '*' } else {'Name', 'Version', 'Description'}
    Invoke-Command -Session $session  -ScriptBlock {
        Get-Module -ListAvailable -Name $using:Name |
            Where-Object Name -notin $using:NeverImportList |
                Select-Object $using:propertiesToReturn
    } |  Select-Object $propertiesToReturn |
        Sort-Object Name
}

function Import-WinModule
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        # Specifies the name of the module to be imported. Wildcards can be used.
        [Parameter(Mandatory=$False,Position=0)]
        [String[]]
            $Name="*",

        # A list of wildcard patterns matching the names of modules that
        # should not be imported.
        [Parameter()]
        [string[]]
            $Exclude = "",

        # If you don't want to use the default compatibility session, use
        # this parameter to specify the name of the computer on which to create
        # the compatibility session.
        [Parameter()]
        [String]
        [Alias("cn")]
            $ComputerName,

        # Specifies the configuration to connect to when creating the compatibility session
        # (Defaults to 'Microsoft.PowerShell')
        [Parameter()]
        [String]
            $ConfigurationName,

        # Prefix to prepend to the imported command names
        [Parameter()]
        [string]
            $Prefix = "",

        # Disable warnings about non-standard verbs
        [Parameter()]
        [Switch]
            $DisableNameChecking,

        # Don't overwrite any existing function definitions
        [Parameter()]
        [Switch]
            $NoClobber,

        # Force reloading the module
        [Parameter()]
        [Switch]
            $Force,

        # The credential to use when creating the compatibility session
        # using the target machine/configuration
        [Parameter()]
        [PSCredential]
            $Credential,

        # If present, the ModuleInfo objects will be written to the output pipe
        # as deserialized (PSObject) objects
        [Parameter()]
        [Switch]
            $PassThru
    )

    [bool] $verboseFlag = $PSBoundParameters['Verbose']

    Write-Verbose -Verbose:$verboseFlag "Connecting to compatibility session."
    $initializeWinSessionParameters = @{
        Verbose           = $verboseFlag
        ComputerName      = $ComputerName
        ConfigurationName = $ConfigurationName
        Credential        = $Credential
        PassThru          = $true
    }
    [PSSession] $session = Initialize-WinSession @initializeWinSessionParameters

    # Mapping wildcards to a regex
    $Exclude = ($Exclude -replace "\*",".*") -join "|"

    Write-Verbose -Verbose:$verboseFlag "Getting module list..."
    $importNames = Invoke-Command -Session $session {
        # Running on the Remote Machine
        $m = (Get-Module -ListAvailable -Name $using:Name).
                Where{ $_.Name -notin $using:NeverImportList }

        # These can use wildcards e.g. Az*,x* will probably be common
        if ($using:Exclude)
        {
            $m = $m.Where{ $_.Name -NotMatch $using:Exclude }
        }

        $m.Name | Select-Object -Unique
    }

    Write-Verbose -Verbose:$verboseFlag "Importing modules..."
    $importModuleParameters = @{
        Global              = $true
        Force               = $Force
        Verbose             = $verboseFlag
        PSSession           = $session
        PassThru            = $PassThru
        DisableNameChecking = $DisableNameChecking
    }
    if ($Prefix)
    {
        $importModuleParameters.Prefix = $Prefix
    }
    if ($PassThru)
    {
        $importModuleParameters.PassThru = $PassThru
    }
    if ($importNames)
    {
        # Extract the 'never clobber' modules from the list
        $noClobberNames = $importNames.where{ $_ -in $script:NeverClobberList }
        $importNames    = $importNames.where{ $_ -notin $script:NeverClobberList }
        if ($importNames)
        {
            Import-Module  -Name $ImportNames -NoClobber:$NoClobber @importModuleParameters
        }
        if ($noClobberNames)
        {
            $importModuleParameters.PassThru = $true
            foreach ($name in $noClobberNames)
            {
                $module = Import-Module -Name $name -NoClobber @importModuleParameters
                # Hack using private reflection to keep the proxy module from shadowing the real module.
                $null = [PSModuleInfo].
                    GetMethod('SetName',[System.Reflection.BindingFlags]'Instance, NonPublic').
                        Invoke($module, @($module.Name + '.WinModule'))
                if($PassThru.IsPresent)
                {
                    $module
                }
            }
        }
    }
    else
    {
        Write-Verbose -Verbose:$verboseFlag "No matching modules were found; nothing was imported"
    }
}

function Compare-WinModule
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        # Specifies the names or name patterns of for the modules to compare.
        # Wildcard characters are permitted.
        [Parameter(Position=0)]
        [String[]]
            $Name="*",

        # If you don't want to use the default compatibility session, use
        # this parameter to specify the name of the computer on which to create
        # the compatibility session.
        [Parameter()]
        [String]
        [Alias("cn")]
            $ComputerName,

        # Specifies the configuration to connect to when creating the compatibility session
        # (Defaults to 'Microsoft.PowerShell')
        [Parameter()]
        [String]
            $ConfigurationName,

        # If needed, use this parameter to specify credentials for the compatibility session
        [Parameter()]
        [PSCredential]
            $Credential
    )

    [bool] $verboseFlag = $PSBoundParameters['Verbose']

    Write-Verbose -Verbose:$verboseFlag "Initializing compatibility session"
    $initializeWinSessionParameters = @{
        Verbose           = $verboseFlag
        ComputerName      = $ComputerName
        ConfigurationName = $ConfigurationName
        Credential        = $Credential
        PassThru          = $true
    }
    [PSSession] $session = Initialize-WinSession @initializeWinSessionParameters

    Write-Verbose -Verbose:$verboseFlag "Getting local modules..."
    $LocalModule = (Get-Module -ListAvailable -Verbose:$false).Where{$_.Name -like $Name}

    Write-Verbose -Verbose:$verboseFlag "Getting remote modules..."
    # Use Invoke-Command here instead of the -PSSession option on Get-Module because
    # we're only returning a subset of the data
    $RemoteModule = @(Invoke-Command -Session $session {
        (Get-Module -ListAvailable).
            Where{$_.Name -notin $using:NeverImportList -and $_.Name -like $using:Name} |
                Select-Object Name, Version })

    Write-Verbose -Verbose:$verboseFlag "Comparing module set..."
    Compare-Object $LocalModule $RemoteModule -Property Name,Version |
        Where-Object SideIndicator -eq "=>"
}

function Copy-WinModule
{
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([void])]
    Param
    (
        # Specifies names or name patterns of modules that will be copied.
        # Wildcard characters are permitted.
        [Parameter(Mandatory=$false,Position=0)]
        [String[]]
            $Name="*",

        # If you don't want to use the default compatibility session, use
        # this parameter to specify the name of the computer on which to create
        # the compatibility session.
        [Parameter()]
        [String]
        [Alias("cn")]
            $ComputerName,

        # Specifies the configuration to connect to when creating the compatibility session
        # (Defaults to 'Microsoft.PowerShell')
        [Parameter()]
        [String]
            $ConfigurationName,

        # If needed, use this parameter to specify credentials for the compatibility session
        [Parameter()]
        [PSCredential]
            $Credential,

        # The location where compatible modules should be copied to
        [Parameter()]
        [String]
            $Destination
    )

    [bool] $verboseFlag = $PSBoundParameters['Verbose']
    [bool] $whatIfFlag  = $PSBoundParameters['WhatIf']
    [bool] $confirmFlag = $PSBoundParameters['Confirm']

    if (-not $Destination)
    {
        # If the user hasn't specified a destination, default to the user module directory
        $parts =  [environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments),
                    "PowerShell",
                        "Modules"
        $Destination = Join-Path @parts
    }

    # Resolve the path which also verifies that the path exists
    $resolvedDestination = Resolve-Path $Destination -ErrorAction SilentlyContinue
    if (-not $?)
    {
        throw "The destination path '$Destination' could not be resolved. Please ensure that the path exists and try the command again"
    }
    # Make sure it's a FileSystem location
    if ($resolvedDestination.provider.ImplementingType -ne [Microsoft.PowerShell.Commands.FileSystemProvider] )
    {
        throw "Modules can only be installed to paths in the filesystem. Please choose a different location and try the command again"
    }
    $Destination = $resolvedDestination.Path

    $initializeWinSessionParameters = @{
        Verbose           = $verboseFlag
        ComputerName      = $ComputerName
        ConfigurationName = $ConfigurationName
        Credential        = $Credential
        PassThru          = $true
    }
    [PSSession] $session = Initialize-WinSession @initializeWinSessionParameters

    $copyItemParameters = @{
        WhatIf  = $whatIfFlag
        Verbose = $verboseFlag
        Confirm = $confirmFlag
        Recurse = $true
    }
    if ($ComputerName -ne "localhost" -and $ComputerName -ne ".")
    {
        $copyItemParameters.FromSession = $session
    }

    Write-Verbose -Verbose:$verboseFlag "Searching for compatible modules..."
    $modulesToCopy = Invoke-Command $session {
        Get-Module -ListAvailable -Name $using:CompatibleModules |
            Select-Object Name, ModuleBase
    }

    Write-Verbose -Verbose:$verboseFlag "Searching for CIM modules..."
    $modulesToCopy += Invoke-Command $session {
        Get-Module -ListAvailable |
            Where-Object { $_.NestedModules[0].path -match '\.cdxml$' } |
                Select-Object Name,ModuleBase
    }

    Write-Verbose -Verbose:$verboseFlag "Copying modules to path '$Destination'"

    $modulesToCopy = $modulesToCopy | Sort-Object -Unique -Property Name
    foreach ($m in $modulesToCopy)
    {
        # Skip modules that aren't on the named module list
        if (-not ($name.Where{$m.Name -like $_}))
        {
            continue
        }

        $fullDestination = Join-Path $Destination $m.name
        if (-not (Test-Path $fullDestination))
        {
            Copy-Item  -Path $m.ModuleBase -Destination $fullDestination @copyItemParameters
        }
        else
        {
            Write-Verbose -Verbose:$verboseFlag "Skipping module '$($m.Name)'; module directory already exists"
        }
    }
}

function Add-WindowsPSModulePath
{
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([void])]
    param ()

    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows)
    {
        throw "This cmdlet is only supported on Windows"
    }

    if ($PSVersionTable.PSEdition -eq 'Desktop')
    {
        return
    }

    [bool] $verboseFlag = $PSBoundParameters['Verbose']
    
    $paths =  @(
        $Env:PSModulePath -split [System.IO.Path]::PathSeparator
        "${Env:UserProfile}\Documents\WindowsPowerShell\Modules"
        "${Env:ProgramFiles}\WindowsPowerShell\Modules"
        "${Env:WinDir}\system32\WindowsPowerShell\v1.0\Modules"
        [System.Environment]::GetEnvironmentVariable('PSModulePath',
            [System.EnvironmentVariableTarget]::User) -split [System.IO.Path]::PathSeparator
        [System.Environment]::GetEnvironmentVariable('PSModulePath',
            [System.EnvironmentVariableTarget]::Machine) -split [System.IO.Path]::PathSeparator
    )

    $pathTable = [ordered] @{}

    foreach ($path in $paths)
    {
        if ($pathTable[$path])
        {
            continue
        }

        if ($PSCmdlet.ShouldProcess($path, "Add to PSModulePath"))
        {
            Write-Verbose -Verbose:$verboseFlag "Adding '$path' to the PSModulePath."
            $pathTable[$path] = $true
        }
    }

    $Env:PSModulePath = $pathTable.Keys -join [System.IO.Path]::PathSeparator
}

# SIG # Begin signature block
# MIIkVgYJKoZIhvcNAQcCoIIkRzCCJEMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDQtMeFF61nQNKp
# BqLAm8eWiLEx695boA8rSj6VMUtfhKCCDYEwggX/MIID56ADAgECAhMzAAABA14l
# HJkfox64AAAAAAEDMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTgwNzEyMjAwODQ4WhcNMTkwNzI2MjAwODQ4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDRlHY25oarNv5p+UZ8i4hQy5Bwf7BVqSQdfjnnBZ8PrHuXss5zCvvUmyRcFrU5
# 3Rt+M2wR/Dsm85iqXVNrqsPsE7jS789Xf8xly69NLjKxVitONAeJ/mkhvT5E+94S
# nYW/fHaGfXKxdpth5opkTEbOttU6jHeTd2chnLZaBl5HhvU80QnKDT3NsumhUHjR
# hIjiATwi/K+WCMxdmcDt66VamJL1yEBOanOv3uN0etNfRpe84mcod5mswQ4xFo8A
# DwH+S15UD8rEZT8K46NG2/YsAzoZvmgFFpzmfzS/p4eNZTkmyWPU78XdvSX+/Sj0
# NIZ5rCrVXzCRO+QUauuxygQjAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUR77Ay+GmP/1l1jjyA123r3f3QP8w
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDM3OTY1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAn/XJ
# Uw0/DSbsokTYDdGfY5YGSz8eXMUzo6TDbK8fwAG662XsnjMQD6esW9S9kGEX5zHn
# wya0rPUn00iThoj+EjWRZCLRay07qCwVlCnSN5bmNf8MzsgGFhaeJLHiOfluDnjY
# DBu2KWAndjQkm925l3XLATutghIWIoCJFYS7mFAgsBcmhkmvzn1FFUM0ls+BXBgs
# 1JPyZ6vic8g9o838Mh5gHOmwGzD7LLsHLpaEk0UoVFzNlv2g24HYtjDKQ7HzSMCy
# RhxdXnYqWJ/U7vL0+khMtWGLsIxB6aq4nZD0/2pCD7k+6Q7slPyNgLt44yOneFuy
# bR/5WcF9ttE5yXnggxxgCto9sNHtNr9FB+kbNm7lPTsFA6fUpyUSj+Z2oxOzRVpD
# MYLa2ISuubAfdfX2HX1RETcn6LU1hHH3V6qu+olxyZjSnlpkdr6Mw30VapHxFPTy
# 2TUxuNty+rR1yIibar+YRcdmstf/zpKQdeTr5obSyBvbJ8BblW9Jb1hdaSreU0v4
# 6Mp79mwV+QMZDxGFqk+av6pX3WDG9XEg9FGomsrp0es0Rz11+iLsVT9qGTlrEOla
# P470I3gwsvKmOMs1jaqYWSRAuDpnpAdfoP7YO0kT+wzh7Qttg1DO8H8+4NkI6Iwh
# SkHC3uuOW+4Dwx1ubuZUNWZncnwa6lL2IsRyP64wggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIWKzCCFicCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAQNeJRyZH6MeuAAAAAABAzAN
# BglghkgBZQMEAgEFAKCBvDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgywa784g1
# p7Rv3mPTlVwGJV6GWr93Vc6Enp4ar+lfSkYwUAYKKwYBBAGCNwIBDDFCMECgFoAU
# AFAAbwB3AGUAcgBTAGgAZQBsAGyhJoAkaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L1Bvd2VyU2hlbGwgMA0GCSqGSIb3DQEBAQUABIIBAFRsUZ53HiHCvweplBBpTO6/
# ekWqMC1Lui9dSc6s7eCReTvdfidkBaOLMFKQhIHX+3RC0tyufH3EzSwOGOLjjhHq
# LdOw2G+7CPh3TVUAdb+4pkNwwGDCXp4nf97pw2aePEbkFAX6S5j8POu5FHZw3BHF
# AedpkycHkSAyqXhDMnDvGqKm6M4AxKo17uvVbAKXwJOJ54fYsAEAvJowbupQTkKc
# rtWRpaqbsOuVIp7u5cch7nBU847H6D4tUpoeKg4S2fJrnuSOnwbRZJlKePYNySYx
# y20OXVcz6fSVYx+uMGR6g9Zl8tA8bZ3ivtINYjv7sVw5rM9xRb2jXXAzI1SFqrGh
# ghOnMIITowYKKwYBBAGCNwMDATGCE5MwghOPBgkqhkiG9w0BBwKgghOAMIITfAIB
# AzEPMA0GCWCGSAFlAwQCAQUAMIIBVAYLKoZIhvcNAQkQAQSgggFDBIIBPzCCATsC
# AQEGCisGAQQBhFkKAwEwMTANBglghkgBZQMEAgEFAAQg7BAzZXEvJO8AlYF6G+us
# 9qLQOlCRavL7N4wf4r1MIxICBlvboKjS2hgTMjAxODExMTQyMzAyMTIuMzkxWjAH
# AgEBgAIB9KCB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQG
# A1UECxMdVGhhbGVzIFRTUyBFU046MTJCNC0yRDVGLTg3RDQxJTAjBgNVBAMTHE1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg8TMIIGcTCCBFmgAwIBAgIKYQmB
# KgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0NjU1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77Xxo
# SyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM1024
# OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0yS
# wcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3WsvYpC
# TUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnN
# POcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHiMBAG
# CSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8E
# TzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBM
# MEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGSMIGP
# BgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0A
# TABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0w
# DQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+zwXi
# qf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKKdsxA
# QEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/UveYFl
# 2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4zu2Jf
# mttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHimbdLh
# nPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlXdqJx
# qgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/n
# MQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A+xuJ
# KlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdCosnP
# GUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42neV8HR
# 3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950
# iEkSMIIE8TCCA9mgAwIBAgITMwAAAOVORWdqcnTRzAAAAAAA5TANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0xODA4MjMyMDI3
# MDlaFw0xOTExMjMyMDI3MDlaMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoxMkI0LTJENUYtODdENDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAOYaYhLcp40eTFtz+2o4HJiHWkRtFBoKsHddXBR7clnP
# vacnYtwA/O5ScLabgVG3SRcUjR80N/CeSpA+rvQun62k/SWKgDMSHrYfg7YWRE5h
# wUXp0FDPxkanVx4otPYQVu4axUGDMgCd7vFFjiikLWfY1iRHpyPiRPDcovoaYlrq
# MZQnxr0UeRYxfzLiL0oMNYWTaDDEZq8u/UZdnC6RrXn61mjUvPn4j17ppt0MnIxe
# FcOLqbS6OQHMLu5By9NQVi0U64D1Cno31hewgG7fggrppjX7pLRMZS8du88WyFzU
# pWIc/X3sGcSqzECWFJm5nRWzNIrMBu3TWjAOLoCCsMkCAwEAAaOCARswggEXMB0G
# A1UdDgQWBBQQ1lngTRwfj+KMIHDzSAhccw5msTAfBgNVHSMEGDAWgBTVYzpcijGQ
# 80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0w
# MS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNy
# dDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# CwUAA4IBAQAxY4a2DNv+03IPVCZrTU8zE5JxPjGgZ0WYN1N4ipXEPW00whUDoR8l
# OUB/QJ2itRo0823cmyUgbc4bAJdVSoXArdyZ6FtlNEvJ9IY5Jf7SrbK+nSWVPFHO
# v356VnBvQIzP0lBsvs3aeQJ5GVds7yifW8qY1dFmfrjd1MKFcCACZJX7oKfVE5NV
# YTn1j0pPj2HTfWvCnrSXP4aqH+X1N4V/hCbdNLDG4TKnQetKeSRF7WkZQpXBwDMI
# 9phyoCu94hopK2jT5kX+6YrYyzYBY9Qeu/E9W0YLgSJGkYwyfKy00Mt3HeOfAK57
# Q14pXUXS62TsTrcN43NfuKj+4S6AIhgxoYIDpTCCAo0CAQEwgfqhgdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjEyQjQtMkQ1Ri04N0Q0MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloiUKAQEwCQYFKw4DAhoFAAMVAKbTADJlgr7EUMjsRfYk544hJp9D
# oIHaMIHXpIHUMIHRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQL
# Ex5uQ2lwaGVyIE5UUyBFU046MjY2NS00QzNGLUM1REUxKzApBgNVBAMTIk1pY3Jv
# c29mdCBUaW1lIFNvdXJjZSBNYXN0ZXIgQ2xvY2swDQYJKoZIhvcNAQEFBQACBQDf
# lw+PMCIYDzIwMTgxMTE0MjExODA3WhgPMjAxODExMTUyMTE4MDdaMHQwOgYKKwYB
# BAGEWQoEATEsMCowCgIFAN+XD48CAQAwBwIBAAICGxkwBwIBAAICGbcwCgIFAN+Y
# YQ8CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAaAKMAgCAQACAxbj
# YKEKMAgCAQACAwehIDANBgkqhkiG9w0BAQUFAAOCAQEAHtr7otGNauFiKiXU9xQH
# MaNLESsQh7Ztks5bWgynQSWDmJnZCxdUfxYhQEA/UK32nZrQZs3ly1/0L2FuEIHK
# D6c78ATmF2odYhhBb6Kz7qgCcsjQWjnaUAmp2mtmsbDN5gmL9Fcb1EEW9pEeaRyH
# nHMezqAVrb631e5mfY5gArZPYHKNCJ3ulxyJJ2ZEt3FtsJMOlCRMItK5jBkh415x
# 2TNfAiGWsB2SQoNOMekFh0vfJ3ukQ6GlbiV2gnihPwED15iv79KcZjrU4Grmrpsw
# uMx6S0w7HhLAHfQJM0m6LBMz04NEgxegcMPHoSzI5iU4QNqJPis8Y0MOY2UaXaLI
# BzGCAvUwggLxAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAAA5U5FZ2pydNHMAAAAAADlMA0GCWCGSAFlAwQCAQUAoIIBMjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIG6kuECx4vRY0l0ydvw0
# 8ztn89Pe0lULRgMa3MPnD0EpMIHiBgsqhkiG9w0BCRACDDGB0jCBzzCBzDCBsQQU
# ptMAMmWCvsRQyOxF9iTnjiEmn0MwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAOVORWdqcnTRzAAAAAAA5TAWBBTPsX7dzZWMjL7D2gEd
# s3BrKLK9mjANBgkqhkiG9w0BAQsFAASCAQAXcU/FCbRN/gHYNRSRHs8MBeCJ2wap
# 89PvX2L31m293K6ZRxJKeazjW50OpIpafSAB/NKmzyXtd1lQz5AbXTrJq6oVUhBt
# WexZoS+2g+fKV1iRPYEJ9CcvlEMXhypOHuT/beYUVUCflzFLb8eg+NSnWl55a7wO
# 5PeDJieKYTXszzTHbuW8NzP9Ab931z7mBWGOx87x84XR1rNVP5qITFbHHgVEmXVv
# /c7D/w+64R9v4xz6X2Q++9h1qrfDXlkK9SakqUgSp1f/hizE52NHhT0xNO199fTF
# 8AWfwPwP5KkMLQC+pm6tAYPp3xHj3De2y1I6oGxd9yEycl0TXpay1M5x
# SIG # End signature block
