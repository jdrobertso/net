# Runs all the tests of the net package. With -Online, http_test also
# uses the internet.
#
#   .\run_tests.ps1 [-Online]

param([switch]$Online)
# goose writes its progress to stderr. Thus the script uses the exit code
# of each step, not $ErrorActionPreference, to find failures.
Push-Location (Join-Path $PSScriptRoot "test")
try {
    # The large compress cases are not in git. Make them if Python is here.
    if (-not (Test-Path "data\gen")) {
        foreach ($py in "py", "python3", "python") {
            if (Get-Command $py -ErrorAction SilentlyContinue) {
                & $py -I make_fixtures.py
                if ($LASTEXITCODE -eq 0) { break }
            }
        }
    }
    foreach ($t in "url_test", "cookie_test", "compress_test", "net_test") {
        goose "$t.goose"
        if ($LASTEXITCODE -ne 0) { throw "$t failed" }
    }
    $exe = Join-Path $env:TEMP "goose_net_http_test.exe"
    goose build -o $exe http_test.goose | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "http_test did not build" }
    if ($Online) { & $exe --online } else { & $exe }
    if ($LASTEXITCODE -ne 0) { throw "http_test failed" }
} finally {
    Pop-Location
}
