param([switch]$CheckOnly)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Refresh-ExecutablePath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user;$env:Path"
}
function Available($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}
function Supported-Python {
    if (Available "py") {
        foreach ($version in @("-3.13", "-3.12", "-3.11")) {
            $candidate = (& py $version -c "import sys; print(sys.executable)" 2>$null | Select-Object -Last 1)
            if ($LASTEXITCODE -eq 0 -and $candidate -and (Test-Path "$candidate")) {
                return [string]$candidate
            }
        }
    }
    if (Available "python") {
        & python -c "import sys; sys.exit(0 if (3, 11) <= sys.version_info[:2] < (3, 14) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return ((& python -c "import sys; print(sys.executable)") | Select-Object -Last 1)
        }
    }
    return $null
}
function Has-PostgreSQL {
    $managed = Join-Path $root '.runtime\tools\postgresql\pgsql\bin'
    if ((Test-Path (Join-Path $managed 'postgres.exe')) -and
        (Test-Path (Join-Path $managed 'initdb.exe'))) {
        $version = & (Join-Path $managed 'postgres.exe') --version
        if ($version -match '([0-9]+)\.' -and [int]$Matches[1] -ge 15) { return $true }
    }
    if ((Available "postgres") -and (Available "initdb")) { return $true }
    foreach ($base in @($env:ProgramFiles, [Environment]::GetEnvironmentVariable("ProgramFiles(x86)"))) {
        if (-not $base) { continue }
        $folder = Join-Path $base "PostgreSQL"
        if (-not (Test-Path $folder)) { continue }
        foreach ($child in (Get-ChildItem $folder -Directory -ErrorAction SilentlyContinue)) {
            $exe = Join-Path $child.FullName "bin\postgres.exe"
            $init = Join-Path $child.FullName "bin\initdb.exe"
            if ((Test-Path $exe) -and (Test-Path $init)) {
                $version = & $exe --version
                if ($version -match '([0-9]+)\.') {
                    if ([int]$Matches[1] -ge 15) { return $true }
                }
            }
        }
    }
    return $false
}
function Ensure-Package($name, $id, [scriptblock]$test) {
    if (& $test) {
        Write-Host "$name available"
        return
    }
    if ($CheckOnly) { throw "$name missing; required package: $id" }
    if (-not (Available "winget")) {
        throw "$name missing. Install $id using the official installer (winget not available)."
    }
    Write-Host "Installing required system prerequisite: $name ($id)"
    & winget install --exact --id $id --source winget --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { throw "System package install failed: $id (exit $LASTEXITCODE)" }
    Refresh-ExecutablePath
    if (-not (& $test)) {
        throw "$name was installed but is not visible yet. Open a new terminal and rerun the launcher."
    }
}
Ensure-Package "Python 3.11-3.13" "Python.Python.3.13" { [bool](Supported-Python) }
Ensure-Package "Git" "Git.Git" { Available "git" }
Ensure-Package "Node.js + npm" "OpenJS.NodeJS.LTS" { (Available "node") -and (Available "npm.cmd") }
Ensure-Package "PostgreSQL 15+" "PostgreSQL.PostgreSQL.17" { Has-PostgreSQL }
$python = Supported-Python
if (-not $python) { throw "Supported Python executable unavailable" }
if ($CheckOnly) {
    Write-Host "SYSTEM_PREREQUISITES_PASS"
    exit 0
}
Set-Location $root
Write-Host "Installing/verifying the framework and private Hugging Face checkpoints..."
& $python (Join-Path $root "scripts\start_framework.py")
exit $LASTEXITCODE
