# Signs real CertEnroll requests with a signer certificate from CurrentUser\My - the function
# insists on a certificate from the Cert: drive. Signer, requests and their keys are removed
# again in AfterAll.

BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    . "$PSScriptRoot\TestCertificateStore.ps1"
    $Script:StoreSnapshot = Get-StoreSnapshot

    $Signer = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddHours(1) `
        -Subject "CN=PesterIntegrationTest-$([Guid]::NewGuid())"
    $Script:SigningCert = Get-Item -Path "Cert:\CurrentUser\My\$($Signer.Thumbprint)"

    function New-TestRequest {
        New-CertificateRequest -Subject "CN=PesterIntegrationTest-$([Guid]::NewGuid())"
    }

    # The signed message, decoded, and the PKCS#10 it carries as Base64
    function ConvertFrom-SignedRequest {
        param([string] $SignedRequest)
        $Cms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
        $Cms.Decode([Convert]::FromBase64String(($SignedRequest -replace '-----[^-]+-----' -replace '\s')))
        $Cms
    }

    function ConvertTo-RequestBytes {
        param([string] $Request)
        [Convert]::FromBase64String(($Request -replace '-----[^-]+-----' -replace '\s'))
    }
}

AfterAll {
    Remove-StoreDelta -Snapshot $Script:StoreSnapshot | Should -BeNullOrEmpty -Because 'tests must not add anything to CurrentUser\Root'
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-SignedCertificateRequest' -Tag 'RequiresWindows' {

    It 'wraps the request in a PKCS#7 message signed by the signing certificate' {
        $Request = New-TestRequest

        $Signed = New-SignedCertificateRequest -CertificateRequest $Request -SigningCert $Script:SigningCert

        $Signed | Should -BeLike '-----BEGIN PKCS #7 SIGNED DATA-----*-----END PKCS #7 SIGNED DATA-----'
        $Cms = ConvertFrom-SignedRequest -SignedRequest $Signed
        { $Cms.CheckSignature($true) } | Should -Not -Throw
        $Cms.SignerInfos[0].Certificate.Thumbprint | Should -Be $Script:SigningCert.Thumbprint
        $Cms.ContentInfo.Content | Should -Be (ConvertTo-RequestBytes -Request $Request)
    }

    It 'hashes with <Algorithm>' -ForEach @(
        @{ Algorithm = 'SHA1'; Oid = '1.3.14.3.2.26' }
        @{ Algorithm = 'SHA256'; Oid = '2.16.840.1.101.3.4.2.1' }
        @{ Algorithm = 'SHA384'; Oid = '2.16.840.1.101.3.4.2.2' }
        @{ Algorithm = 'SHA512'; Oid = '2.16.840.1.101.3.4.2.3' }
    ) {
        $Signed = New-SignedCertificateRequest -CertificateRequest (New-TestRequest) -SigningCert $Script:SigningCert -SignatureHashAlgorithm $Algorithm

        (ConvertFrom-SignedRequest -SignedRequest $Signed).SignerInfos[0].DigestAlgorithm.Value | Should -Be $Oid
    }

    It 'adds the requester name for an enroll-on-behalf-of request' {
        $Signed = New-SignedCertificateRequest -CertificateRequest (New-TestRequest) -SigningCert $Script:SigningCert -RequesterName 'CONTOSO\jdoe'

        # szOID_ENROLLMENT_NAME_VALUE_PAIR, a BMPString pair of "requestername" and the name
        $Attribute = (ConvertFrom-SignedRequest -SignedRequest $Signed).SignerInfos[0].SignedAttributes |
            Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.13.2.1' }
        $Attribute | Should -Not -BeNullOrEmpty
        $Raw = [System.Text.Encoding]::BigEndianUnicode.GetString($Attribute.Values[0].RawData)
        $Raw | Should -BeLike '*CONTOSO\jdoe*'
    }

    It 'signs every request piped in' {
        $Requests = @(New-TestRequest; New-TestRequest)

        $Signed = @($Requests | New-SignedCertificateRequest -SigningCert $Script:SigningCert)

        $Signed.Count | Should -Be 2
        (ConvertFrom-SignedRequest -SignedRequest $Signed[1]).ContentInfo.Content | Should -Be (ConvertTo-RequestBytes -Request $Requests[1])
    }

    It 'writes an error for something that is not a request' {
        $Result = New-SignedCertificateRequest -CertificateRequest 'not a request' -SigningCert $Script:SigningCert -ErrorAction SilentlyContinue -ErrorVariable Errors

        $Result | Should -BeNullOrEmpty
        $Errors | Should -Not -BeNullOrEmpty
    }

    It 'rejects <Case>' -ForEach @(
        @{ Case = 'a requester name without a domain'; Parameters = @{ RequesterName = 'jdoe' } }
        @{ Case = 'an unknown hash algorithm'; Parameters = @{ SignatureHashAlgorithm = 'MD5' } }
    ) {
        { New-SignedCertificateRequest -CertificateRequest 'irrelevant' -SigningCert $Script:SigningCert @Parameters } |
            Should -Throw -ErrorId 'ParameterArgumentValidationError,New-SignedCertificateRequest'
    }

    It 'rejects a signing certificate that is not from a certificate store' {
        $InMemory = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Script:SigningCert.RawData)

        { New-SignedCertificateRequest -CertificateRequest 'irrelevant' -SigningCert $InMemory } |
            Should -Throw -ErrorId 'ParameterArgumentValidationError,New-SignedCertificateRequest'
    }
}
