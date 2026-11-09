[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)
$curr = (Get-Location).Path
$converted = @()
foreach ($a in $RemainingArgs) {
    $converted += ($a -replace '\\', '/')
}
& wsl.exe --cd "$curr" -d Ubuntu -u root -- toolcage $converted
exit $LASTEXITCODE
