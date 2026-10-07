BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    # In-memory signer only - nothing is written to a certificate store
    $Key = [System.Security.Cryptography.RSA]::Create(2048)
    $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=PesterTest Signer', $Key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $Script:Signer = $Request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))

    $Script:Data = [System.Text.Encoding]::ASCII.GetBytes('data to sign')

    function ConvertFrom-SignedCms {
        param([byte[]] $Encoded, [bool] $Detached)
        $Cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
            [System.Security.Cryptography.Pkcs.ContentInfo]::new([byte[]]$Script:Data), $Detached)
        $Cms.Decode($Encoded)
        $Cms
    }
}

AfterAll {
    $Script:Signer.Dispose()
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-SignedCms' {

    It 'signs the data with the signer certificate and embeds it' {
        $Encoded = InModuleScope PSCertificateEnrollment -Parameters @{ Data = $Script:Data; Signer = $Script:Signer } {
            param($Data, $Signer)
            New-SignedCms -DataToSign $Data -SignerCertificate $Signer
        }

        $Cms = ConvertFrom-SignedCms -Encoded $Encoded -Detached $false

        $Cms.Detached | Should -BeFalse
        $Cms.ContentInfo.Content | Should -Be $Script:Data
        $Cms.SignerInfos.Count | Should -Be 1
        $Cms.SignerInfos[0].Certificate.Thumbprint | Should -Be $Script:Signer.Thumbprint
        { $Cms.CheckSignature($true) } | Should -Not -Throw
    }

    It 'leaves the data out with -Detached' {
        $Encoded = InModuleScope PSCertificateEnrollment -Parameters @{ Data = $Script:Data; Signer = $Script:Signer } {
            param($Data, $Signer)
            New-SignedCms -DataToSign $Data -SignerCertificate $Signer -Detached
        }

        # Decoding with the content supplied separately only verifies if the signature covers it
        $Cms = ConvertFrom-SignedCms -Encoded $Encoded -Detached $true

        $Cms.Detached | Should -BeTrue
        { $Cms.CheckSignature($true) } | Should -Not -Throw
        [System.Text.Encoding]::ASCII.GetString($Encoded) | Should -Not -BeLike '*data to sign*'
    }

    It 'fails for a signer certificate without a private key' {
        InModuleScope PSCertificateEnrollment -Parameters @{ Data = $Script:Data; RawData = $Script:Signer.RawData } {
            param($Data, $RawData)
            $PublicOnly = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$RawData)
            { New-SignedCms -DataToSign $Data -SignerCertificate $PublicOnly } | Should -Throw
        }
    }
}
