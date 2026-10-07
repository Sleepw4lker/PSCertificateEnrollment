# Installs certificates for real pending requests in CurrentUser\REQUEST. The issuing CA only
# exists in memory - it never enters a store, so nothing is trusted and nothing lands in Root.
# Requests, installed certificates and their keys are removed again in AfterAll.

BeforeDiscovery {
    $IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    . "$PSScriptRoot\TestCertificateStore.ps1"
    $Script:StoreSnapshot = Get-StoreSnapshot

    $Script:CaKey = [System.Security.Cryptography.RSA]::Create(2048)
    $CaRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=PesterIntegrationTest Install CA', $Script:CaKey, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $CaRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $Script:CaCert = $CaRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(1))

    # Creates a pending request with New-CertificateRequest and has the in-memory CA issue a
    # certificate for its key. Works on .NET Framework too: the public key comes from the
    # placeholder in CurrentUser\REQUEST rather than from parsing the PKCS#10.
    function New-IssuedCertificate {
        $Subject = "CN=PesterIntegrationTest-$([Guid]::NewGuid())"
        $null = New-CertificateRequest -Subject $Subject
        $Pending = Get-TestStoreCertificate -StoreName REQUEST | Where-Object Subject -eq $Subject

        $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Subject), $Pending.PublicKey, 'SHA256')
        $Generator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA(
            $Script:CaKey, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $Serial = [byte[]](1..8 | ForEach-Object { Get-Random -Minimum 1 -Maximum 255 })
        $Request.Create($Script:CaCert.SubjectName, $Generator, [DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1), $Serial)
    }

    function Test-Pending {
        param([string] $Subject)
        [bool](Get-TestStoreCertificate -StoreName REQUEST | Where-Object Subject -eq $Subject)
    }
}

AfterAll {
    Remove-StoreDelta -Snapshot $Script:StoreSnapshot | Should -BeNullOrEmpty -Because 'tests must not add anything to CurrentUser\Root'
    $Script:CaCert.Dispose()
    $Script:CaKey.Dispose()
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Install-IssuedCertificate' -Tag 'RequiresWindows' {

    It 'installs the certificate with the key of its pending request' {
        $Issued = New-IssuedCertificate

        $Installed = Install-IssuedCertificate -Certificate $Issued -Force

        $Installed.Thumbprint | Should -Be $Issued.Thumbprint
        $Installed.HasPrivateKey | Should -BeTrue
        $Installed.PSParentPath | Should -BeLike '*CurrentUser\My'
        Test-Pending -Subject $Issued.Subject | Should -BeFalse
    }

    It 'sets the friendly name' {
        $Issued = New-IssuedCertificate

        $null = Install-IssuedCertificate -Certificate $Issued -Force -FriendlyName 'Pester Friendly Name'

        (Get-Item -Path "Cert:\CurrentUser\My\$($Issued.Thumbprint)").FriendlyName | Should -Be 'Pester Friendly Name'
    }

    It 'installs a certificate read from a file' {
        $Issued = New-IssuedCertificate
        $File = Join-Path $TestDrive "$($Issued.Thumbprint).cer"
        [System.IO.File]::WriteAllBytes($File, $Issued.RawData)

        (Install-IssuedCertificate -Path $File -Force).Thumbprint | Should -Be $Issued.Thumbprint
    }

    It 'refuses a certificate from an untrusted CA without -Force' {
        $Issued = New-IssuedCertificate

        { Install-IssuedCertificate -Certificate $Issued -ErrorAction Stop } | Should -Throw
        Test-Path -Path "Cert:\CurrentUser\My\$($Issued.Thumbprint)" | Should -BeFalse
        Test-Pending -Subject $Issued.Subject | Should -BeTrue
    }

    It 'writes an error for a file that holds no certificate' {
        $File = Join-Path $TestDrive 'not-a-certificate.cer'
        Set-Content -Path $File -Value 'not a certificate'

        { Install-IssuedCertificate -Path $File -Force -ErrorAction Stop } | Should -Throw
    }

    It 'refuses -MachineContext without elevation' -Skip:$IsElevated {
        $Issued = New-IssuedCertificate

        { Install-IssuedCertificate -Certificate $Issued -MachineContext -Force -ErrorAction Stop } | Should -Throw '*Elevation*'
    }
}
