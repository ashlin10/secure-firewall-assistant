param([Parameter(ValueFromRemainingArguments = $true)][string[]]$SfaArguments)
$ErrorActionPreference = 'Stop'
$SfaUv = (Get-Command uv -ErrorAction SilentlyContinue).Source
if (-not $SfaUv) { throw 'Install uv first; see README.md.' }
if (-not $SfaArguments) { $SfaArguments = @('--help') }
& $SfaUv run --project $PSScriptRoot --frozen --no-dev --offline secure-firewall-assistant @SfaArguments
exit $LASTEXITCODE
