$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    python -m unittest discover -s tests -v
}
finally {
    Pop-Location
}
