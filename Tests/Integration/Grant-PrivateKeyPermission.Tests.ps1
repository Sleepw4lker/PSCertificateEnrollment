# Changes the permissions of real private keys in CurrentUser\My. The certificates and their keys,
# permissions included, are removed again in AfterAll.

BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    . "$PSScriptRoot\TestCertificateStore.ps1"
    $Script:StoreSnapshot = Get-StoreSnapshot

    $Script:LegacyCsp = @{ Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'; KeySpec = 'KeyExchange' }

    function New-TestCertificate {
        param([hashtable] $KeyParameters)
        $Certificate = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddHours(1) `
            -Subject "CN=PesterIntegrationTest-$([Guid]::NewGuid())" @KeyParameters
        Get-Item -Path "Cert:\CurrentUser\My\$($Certificate.Thumbprint)"
    }

    # The SIDs allowed on the certificate's private key, read without the function under test
    function Get-KeyAllowedSid {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

        $Key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if (-not $Key) {
            $Key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
        }

        try {
            $Descriptor = $Key.Key.GetProperty('Security Descr', [System.Security.Cryptography.CngPropertyOptions]4) # DACL_SECURITY_INFORMATION
            $Security = [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$Descriptor.GetValue(), 0)
            $Security.DiscretionaryAcl | Where-Object AceType -eq 'AccessAllowed' | ForEach-Object { $_.SecurityIdentifier.Value }
        }
        finally {
            $Key.Dispose()
        }
    }
}

AfterAll {
    Remove-StoreDelta -Snapshot $Script:StoreSnapshot | Should -BeNullOrEmpty -Because 'tests must not add anything to CurrentUser\Root'
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Grant-PrivateKeyPermission' -Tag 'RequiresWindows' {

    It 'grants NETWORK SERVICE access to <Case>' -ForEach @(
        @{ Case = 'an RSA key in a key storage provider'; KeyParameters = @{ Provider = 'Microsoft Software Key Storage Provider' } }
        @{ Case = 'an ECDSA key in a key storage provider'; KeyParameters = @{ KeyAlgorithm = 'ECDSA_nistP256' } }
    ) {
        $Certificate = New-TestCertificate -KeyParameters $KeyParameters
        Get-KeyAllowedSid -Certificate $Certificate | Should -Not -Contain 'S-1-5-20'

        $Result = Grant-PrivateKeyPermission -Certificate $Certificate -ErrorAction Stop

        $Result.Thumbprint | Should -Be $Certificate.Thumbprint
        Get-KeyAllowedSid -Certificate $Certificate | Should -Contain 'S-1-5-20'
    }

    # Neither CNG nor .NET's CAPI wrappers can change their permissions without extra privileges
    It 'explains that keys in a legacy CSP are not supported' {
        $Certificate = New-TestCertificate -KeyParameters $Script:LegacyCsp

        { Grant-PrivateKeyPermission -Certificate $Certificate -ErrorAction Stop } | Should -Throw '*legacy CSP*not supported*'
    }

    It 'grants access to another identity' {
        $Certificate = New-TestCertificate -KeyParameters @{ Provider = 'Microsoft Software Key Storage Provider' }

        $null = Grant-PrivateKeyPermission -Certificate $Certificate -Identity 'NT AUTHORITY\LOCAL SERVICE' -ErrorAction Stop

        Get-KeyAllowedSid -Certificate $Certificate | Should -Contain 'S-1-5-19'
    }

    It 'adds the permission only once when granted twice' {
        $Certificate = New-TestCertificate -KeyParameters @{ Provider = 'Microsoft Software Key Storage Provider' }

        $null = Grant-PrivateKeyPermission -Certificate $Certificate -ErrorAction Stop
        $null = Grant-PrivateKeyPermission -Certificate $Certificate -ErrorAction Stop

        @(Get-KeyAllowedSid -Certificate $Certificate | Where-Object { $_ -eq 'S-1-5-20' }).Count | Should -Be 1
    }

    It 'rejects a certificate that is not from a certificate store' {
        $Certificate = New-TestCertificate -KeyParameters @{}
        $InMemory = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate.RawData)

        { Grant-PrivateKeyPermission -Certificate $InMemory } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Grant-PrivateKeyPermission'
    }
}
