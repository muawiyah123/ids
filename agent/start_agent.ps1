param(
    [Parameter(Mandatory = $true)]
    [string]$AgentId,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [Parameter(Mandatory = $true)]
    [string]$ServerUrl
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv (Join-Path $ProjectRoot ".venv")
    } else {
        & python -m venv (Join-Path $ProjectRoot ".venv")
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the agent's Python environment. Install Python 3 and try again."
    }
}

& $Python -c "import scapy.all, aiohttp" *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing the agent's required packages..."
    & $Python -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "Package installation failed. Check your internet connection and try again."
    }
}

Write-Host "Starting the network agent. Keep this window open while monitoring."
& $Python (Join-Path $PSScriptRoot "ids_agent.py") `
    --server-url $ServerUrl `
    --agent-id $AgentId `
    --token $Token `
    --interval 5
exit $LASTEXITCODE
