# Store bookkeeping for the integration tests, dot-sourced by them and by Remove-TestArtifacts.ps1.
#
# Everything a test adds to the CurrentUser certificate stores has to go again, private keys
# included - the CI runner is a long-lived machine. The stores are read with IncludeArchived,
# because listing the Cert: drive does not show archived certificates.
#
# Root is only ever checked, never cleaned: removing from CurrentUser\Root shows a confirmation
# dialog, which would block a non-interactive run. Tests must not put anything there.

$Script:TestCertificateStores = @('My', 'REQUEST', 'CA')

function Get-TestStoreCertificate {
    param([Parameter(Mandatory)][string] $StoreName)

    $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, 'CurrentUser')
    $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, IncludeArchived')
    try {
        # Copy, so the certificates outlive the store handle
        @($Store.Certificates | ForEach-Object { [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_) })
    }
    finally {
        $Store.Close()
    }
}

# Thumbprints of everything in the stores a test may touch, plus Root
function Get-StoreSnapshot {
    $Snapshot = @{}
    foreach ($StoreName in $Script:TestCertificateStores + 'Root') {
        $Snapshot[$StoreName] = @(Get-TestStoreCertificate -StoreName $StoreName | ForEach-Object Thumbprint)
    }
    $Snapshot
}

# Removes certificates and their private keys from the test stores and returns what was removed.
# The filter gets each certificate and the name of its store: & $Filter $Certificate $StoreName
function Remove-TestStoreCertificate {
    param([Parameter(Mandatory)][scriptblock] $Filter)

    foreach ($StoreName in $Script:TestCertificateStores) {
        foreach ($Certificate in @(Get-TestStoreCertificate -StoreName $StoreName | Where-Object { & $Filter $_ $StoreName })) {

            # A path to the certificate reaches archived ones too, and -DeleteKey handles CNG as
            # well as legacy CSP keys
            Remove-Item -LiteralPath "Cert:\CurrentUser\$StoreName\$($Certificate.Thumbprint)" -DeleteKey:$Certificate.HasPrivateKey -Force -ErrorAction Stop

            [PSCustomObject]@{ Store = $StoreName; Thumbprint = $Certificate.Thumbprint; Subject = $Certificate.Subject }
        }
    }
}

# Removes everything added since the snapshot was taken. Returns what landed in Root, which the
# caller should treat as a failure.
function Remove-StoreDelta {
    param([Parameter(Mandatory)][hashtable] $Snapshot)

    $null = Remove-TestStoreCertificate -Filter {
        param($Certificate, $StoreName)
        $Certificate.Thumbprint -notin $Snapshot[$StoreName]
    }

    @(Get-TestStoreCertificate -StoreName 'Root' | Where-Object { $_.Thumbprint -notin $Snapshot['Root'] })
}
