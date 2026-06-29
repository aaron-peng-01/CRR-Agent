param(
    [string]$Config = "configs/default.json",
    [string]$OutDir = "output",
    [int]$NumCases = 0,
    [string]$Python = ""
)

if ([string]::IsNullOrWhiteSpace($Python)) {
    $candidate = Join-Path $PSScriptRoot "..\..\..\.venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $candidate) {
        $Python = (Resolve-Path -LiteralPath $candidate).Path
    } else {
        $Python = "python"
    }
}

$argsList = @("experiments/run_all.py", "--config", $Config, "--out-dir", $OutDir)
if ($NumCases -gt 0) {
    $argsList += @("--num-cases", "$NumCases")
}
& $Python @argsList
