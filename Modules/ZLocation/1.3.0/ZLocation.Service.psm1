Set-StrictMode -Version Latest

Import-Module -Prefix DB (Join-Path $PSScriptRoot 'ZLocation.LiteDB.psd1')

class Service {
    [Collections.Generic.IEnumerable[Location]] Get() {
        return (dboperation {
            # Return an enumerator of all location entries
            [Location[]]$arr = DBFind $collection ([LiteDB.Query]::All()) ([Location])
            ,$arr
        })
    }
    [void] Add([string]$path, [double]$weight) {
        dboperation {
            $l = DBGetById $collection $path ([Location])
            if($l) {
                $l.weight += $weight
                DBUpdate $collection $l
            } else {
                $l = [Location]::new()
                $l.path = $path
                $l.weight = $weight
                DBInsert $collection $l
            }
        }
    }
    [void] Remove([string]$path) {
        dboperation {
            # Use DB's internal column name, not mapped name
            DBDelete $collection ([LiteDB.Query]::EQ('_id', [LiteDB.BSONValue]::new($path)))
        }
    }
}

class Location {
    [LiteDB.BsonId()]
    [string] $path;

    [double] $weight;
}

function Get-ZLocationDatabaseFilePath
{
    return (Join-Path $HOME 'z-location.db')
}
# Returns path to legacy ZLocation backup file.
function Get-ZLocationLegacyBackupFilePath
{
    if($env:USERPROFILE -ne $null) {
        Join-Path $env:USERPROFILE 'z-location.txt'
    }
}

<#
 Open database, invoke a database operation, and close the database afterwards.
 This is necessary for safe multi-process concurrency.
 See: https://github.com/mbdavid/LiteDB/wiki/Concurrency
 Exposes $db and $collection variables for use by the $scriptblock
#>
function dboperation($private:scriptblock) {
    $Private:Mode = if (Get-Variable IsMacOS -ErrorAction Ignore) { 'Exclusive' } else { 'Shared' }
    # $db and $collection will be in-scope within $scriptblock
    $db = DBOpen "Filename=$( Get-ZLocationDatabaseFilePath ); Mode=$Mode"
    $collection = Get-DBCollection $db 'location'
    try {
        # retry logic: on Mac we may not be able to execute the read concurrently
        for ($__i=0; $__i -lt 5; $__i++) {
            try {
                & $private:scriptblock
                return
            } catch {
                $rand = Get-Random 100
                Start-Sleep -Milliseconds (($__i + 1) * 100 - $rand)
            }
        }
        Write-Error $error[0]
        throw 'Cannot execute database operation after 5 attempts, please open an issue on https://github.com/vors/ZLocation'
    } finally {
        $db.dispose()
    }
}

$dbExists = Test-Path (Get-ZLocationDatabaseFilePath)
$legacyBackupPath = Get-ZLocationLegacyBackupFilePath
$legacyBackupExists = ($legacyBackupPath -ne $null) -and (Test-Path $legacyBackupPath)

# Create empty db, collection, and index if it doesn't exist
dboperation {
    $collection.EnsureIndex('path')
}

$service = [Service]::new()

# Migrate legacy backup into database if appropriate
if((-not $dbExists) -and $legacyBackupExists) {
    Write-Warning "ZLocation changed storage from $legacyBackupPath to $(Get-ZLocationDatabaseFilePath), feel free to remove the old txt file"
    Get-Content $legacyBackupPath | Where-Object { $_ -ne $null } | ForEach-Object {
        $split = $_ -split "`t"
        $service.add($split[0], $split[1])
    }
}

Function Get-ZService {
    ,$service
}
