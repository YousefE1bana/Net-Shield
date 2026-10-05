param([string]$Python = 'python', [string]$Environment = '.venv')
$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $repository
if (Test-Path -LiteralPath $Environment) { throw 'Choose a new environment directory; existing environments are preserved.' }
& $Python -m venv $Environment
if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed.' }
$runtime = Join-Path $Environment 'Scripts/python.exe'
& $runtime -m pip install .
if ($LASTEXITCODE -ne 0) { throw 'Installation failed.' }
& $runtime -m netshield init
if ($LASTEXITCODE -ne 0) { throw 'Database initialization failed.' }
Write-Output "Installed observe-only. Bootstrap with: $runtime -m netshield operator-add yousef"
