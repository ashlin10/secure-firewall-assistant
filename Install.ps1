param([string]$Rollback)
$ErrorActionPreference = 'Stop'
$SfaUv = (Get-Command uv -ErrorAction SilentlyContinue).Source
if (-not $SfaUv) { throw 'Install uv first: https://docs.astral.sh/uv/getting-started/installation/' }
$SfaArgs = @('run', '--no-project', '--python', '3.12', (Join-Path $PSScriptRoot 'scripts/install.py'))
if ($Rollback) { $SfaArgs += @('--rollback', $Rollback) }
& $SfaUv @SfaArgs
exit $LASTEXITCODE
