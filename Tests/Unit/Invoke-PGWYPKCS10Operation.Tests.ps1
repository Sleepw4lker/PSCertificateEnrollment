BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    # In-memory certificate only - nothing is written to a certificate store
    $Key = [System.Security.Cryptography.RSA]::Create(2048)
    $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=PesterTest vRO', $Key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $Script:ClientCertificate = $Request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))

    # Long enough for InsertLineBreaks to wrap the Base64
    $Script:RequestBytes = [byte[]](1..200 | ForEach-Object { $_ % 256 })
    $Script:SignatureBytes = [byte[]](200..1 | ForEach-Object { $_ % 256 })

    # Splits the multipart/form-data body the function sent into its parts
    function Get-SentParts {
        $Boundary = [regex]::Match($Script:SentHeaders['Content-Type'], '^multipart/form-data; boundary=(.+)$').Groups[1].Value
        $Boundary | Should -Not -BeNullOrEmpty

        $Script:SentBody | Should -BeLike "--$Boundary`r`n*"
        $Script:SentBody | Should -BeLike "*`r`n--$Boundary--`r`n"

        $Script:SentBody.Substring(0, $Script:SentBody.LastIndexOf("--$Boundary--")) -split [regex]::Escape("--$Boundary`r`n") |
            Where-Object { $_ } |
                ForEach-Object {
                    $Header, $Content = $_ -split "`r`n`r`n", 2
                    [PSCustomObject]@{
                        Name    = [regex]::Match($Header, 'name="([^"]+)"').Groups[1].Value
                        Header  = $Header
                        Content = [Convert]::FromBase64String($Content)
                    }
                }
    }
}

AfterAll {
    $Script:ClientCertificate.Dispose()
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-PGWYPKCS10Operation' {

    BeforeEach {
        $Script:SentBody = $null
        $Script:SentHeaders = $null
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment {
            $Script:SentBody = $Body
            $Script:SentHeaders = $Headers
            [PSCustomObject]@{ StatusCode = 200 }
        }
    }

    It 'POSTs to the URI with the client certificate and returns the response' {
        $Result = InModuleScope PSCertificateEnrollment -Parameters @{ Certificate = $Script:ClientCertificate; Bytes = $Script:RequestBytes } {
            param($Certificate, $Bytes)
            Invoke-PGWYPKCS10Operation -Uri 'https://cm.contoso.com:8444/api/pkcs10' -CertificateRequest $Bytes -ClientCertificate $Certificate
        }

        $Result.StatusCode | Should -Be 200
        Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://cm.contoso.com:8444/api/pkcs10' -and
            $Method -eq 'POST' -and
            $Certificate.Thumbprint -eq $Script:ClientCertificate.Thumbprint -and
            $Headers['Accept'] -eq 'application/pkix-cert'
        }
    }

    It 'sends only the pkcs10 part without -SignedData' {
        InModuleScope PSCertificateEnrollment -Parameters @{ Certificate = $Script:ClientCertificate; Bytes = $Script:RequestBytes } {
            param($Certificate, $Bytes)
            Invoke-PGWYPKCS10Operation -Uri 'https://cm.contoso.com:8444/api/pkcs10' -CertificateRequest $Bytes -ClientCertificate $Certificate
        }

        $Parts = @(Get-SentParts)
        $Parts.Name | Should -Be @('pkcs10')
        $Parts[0].Header | Should -BeLike '*Content-Type: application/pkcs10*'
        $Parts[0].Content | Should -Be $Script:RequestBytes
    }

    It 'adds the signature part for -SignedData' {
        InModuleScope PSCertificateEnrollment -Parameters @{ Certificate = $Script:ClientCertificate; Bytes = $Script:RequestBytes; Signature = $Script:SignatureBytes } {
            param($Certificate, $Bytes, $Signature)
            Invoke-PGWYPKCS10Operation -Uri 'https://cm.contoso.com:8444/api/pkcs10' -CertificateRequest $Bytes -ClientCertificate $Certificate -SignedData $Signature
        }

        $Parts = @(Get-SentParts)
        $Parts.Name | Should -Be @('pkcs10', 'signature')
        $Parts[0].Content | Should -Be $Script:RequestBytes
        $Parts[1].Content | Should -Be $Script:SignatureBytes
    }

    It 'uses a new boundary for every request' {
        InModuleScope PSCertificateEnrollment -Parameters @{ Certificate = $Script:ClientCertificate; Bytes = $Script:RequestBytes } {
            param($Certificate, $Bytes)
            Invoke-PGWYPKCS10Operation -Uri 'https://cm.contoso.com:8444/api/pkcs10' -CertificateRequest $Bytes -ClientCertificate $Certificate
        }
        $First = $Script:SentHeaders['Content-Type']

        InModuleScope PSCertificateEnrollment -Parameters @{ Certificate = $Script:ClientCertificate; Bytes = $Script:RequestBytes } {
            param($Certificate, $Bytes)
            Invoke-PGWYPKCS10Operation -Uri 'https://cm.contoso.com:8444/api/pkcs10' -CertificateRequest $Bytes -ClientCertificate $Certificate
        }

        $Script:SentHeaders['Content-Type'] | Should -Not -Be $First
    }
}
