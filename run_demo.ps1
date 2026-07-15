$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    python -m examples.demo
}
finally {
    Pop-Location
}
