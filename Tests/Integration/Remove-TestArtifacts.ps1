<#
    .SYNOPSIS
    Removes whatever the integration tests may have left in the CurrentUser certificate stores.

    .DESCRIPTION
    A safety net next to the tests' own cleanup, which does not run when a job is cancelled or
    killed. Removes every certificate whose subject starts with CN=PesterIntegrationTest from the
    CurrentUser My, REQUEST and CA stores - archived ones included - together with its private key.
    Only reports test certificates in CurrentUser\Root: removing from there needs a confirmation
    dialog.

    .PARAMETER FailIfFound
    Exits with 1 when anything was found, so a leaking test shows up as a failed job.
#>
[CmdletBinding()]
param(
    [switch] $FailIfFound
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\TestCertificateStore.ps1"

$IsTestCertificate = { param($Certificate) $Certificate.Subject -like 'CN=PesterIntegrationTest*' }

$Removed = @(Remove-TestStoreCertificate -Filter $IsTestCertificate)
$Removed | ForEach-Object { "Removed $($_.Store) $($_.Thumbprint) $($_.Subject)" }

$InRoot = @(Get-TestStoreCertificate -StoreName 'Root' | Where-Object { & $IsTestCertificate $_ })
$InRoot | ForEach-Object { "Found in Root, remove by hand: $($_.Thumbprint) $($_.Subject)" }

if (-not ($Removed -or $InRoot)) {
    'No test certificates left behind.'
}
elseif ($FailIfFound) {
    "$($Removed.Count + $InRoot.Count) test certificate(s) were left behind by the test run."
    exit 1
}
