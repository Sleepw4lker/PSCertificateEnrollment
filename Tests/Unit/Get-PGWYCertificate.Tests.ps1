BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    # In-memory certificates only - nothing is written to a certificate store
    function New-TestCertificate {
        param([string] $Subject)
        $Key = [System.Security.Cryptography.RSA]::Create(2048)
        $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject, $Key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $Request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
    }

    function New-IssuedResponse {
        [PSCustomObject]@{
            StatusCode = 200
            Headers    = @{ 'Content-Type' = 'application/pkix-cert' }
            Content    = $Script:IssuedCertificate.RawData
        }
    }

    function New-JsonResponse {
        param([hashtable] $Json, [int] $StatusCode = 200)
        [PSCustomObject]@{
            StatusCode = $StatusCode
            Headers    = @{ 'Content-Type' = 'application/json' }
            Content    = $Json | ConvertTo-Json -Compress
        }
    }

    $Script:ClientCertificate = New-TestCertificate -Subject 'CN=PesterTest vRO Client'
    $Script:SignerCertificate = New-TestCertificate -Subject 'CN=PesterTest vRO Signer'
    $Script:IssuedCertificate = New-TestCertificate -Subject 'CN=PesterTest Issued'

    # Arbitrary 40-hex thumbprints - Get-CertificateByThumbprint is mocked to resolve them
    $Script:ClientThumbprint = 'C' * 40
    $Script:SignerThumbprint = 'D' * 40

    $Script:Csr = "-----BEGIN NEW CERTIFICATE REQUEST-----`r`nAQID`r`n-----END NEW CERTIFICATE REQUEST-----`r`n"
    $Script:ServerChallenge = [byte[]](9, 8, 7)
    $Script:Signature = [byte[]](4, 5, 6)
}

AfterAll {
    $Script:ClientCertificate, $Script:SignerCertificate, $Script:IssuedCertificate | ForEach-Object { $_.Dispose() }
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-PGWYCertificate' {

    BeforeEach {
        Mock Get-CertificateByThumbprint -ModuleName PSCertificateEnrollment -ParameterFilter { $Thumbprint -eq $Script:ClientThumbprint } { $Script:ClientCertificate }
        Mock Get-CertificateByThumbprint -ModuleName PSCertificateEnrollment -ParameterFilter { $Thumbprint -eq $Script:SignerThumbprint } { $Script:SignerCertificate }
        Mock New-SignedCms -ModuleName PSCertificateEnrollment { $Script:Signature }
    }

    Context 'certificate issued on the first request' {

        BeforeEach {
            Mock Invoke-PGWYPKCS10Operation -ModuleName PSCertificateEnrollment { New-IssuedResponse }
        }

        It 'returns the issued certificate' {
            $Result = Get-PGWYCertificate -CertificateRequest $Script:Csr -ComputerName 'cm.contoso.com' -ClientCertificate $Script:ClientThumbprint -ErrorAction Stop

            $Result | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $Result.Thumbprint | Should -Be $Script:IssuedCertificate.Thumbprint
        }

        It 'submits the decoded request to the default port with the client certificate' {
            $null = Get-PGWYCertificate -CertificateRequest $Script:Csr -ComputerName 'cm.contoso.com' -ClientCertificate $Script:ClientThumbprint -ErrorAction Stop

            Should -Invoke Invoke-PGWYPKCS10Operation -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://cm.contoso.com:8444/api/pkcs10' -and
                [Convert]::ToBase64String($CertificateRequest) -eq 'AQID' -and
                $ClientCertificate.Thumbprint -eq $Script:ClientCertificate.Thumbprint -and
                -not $PesterBoundParameters.ContainsKey('SignedData')
            }
            Should -Invoke New-SignedCms -ModuleName PSCertificateEnrollment -Times 0 -Exactly
        }
    }

    Context 'server asks for a signed request' {

        BeforeEach {
            $Script:Call = 0
            Mock Invoke-PGWYPKCS10Operation -ModuleName PSCertificateEnrollment {
                $Script:Call++
                if ($Script:Call -eq 1) {
                    New-JsonResponse @{ msg = 'Sign request and send again'; DataToSign = [Convert]::ToBase64String($Script:ServerChallenge) }
                }
                else {
                    New-IssuedResponse
                }
            }
        }

        It 'signs DataToSign and sends the request again with the signature' {
            $Result = Get-PGWYCertificate -CertificateRequest $Script:Csr -ComputerName 'cm.contoso.com' -ClientCertificate $Script:ClientThumbprint -SignerCertificate $Script:SignerThumbprint

            $Result.Thumbprint | Should -Be $Script:IssuedCertificate.Thumbprint
            Should -Invoke New-SignedCms -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                [Convert]::ToBase64String($DataToSign) -eq [Convert]::ToBase64String($Script:ServerChallenge) -and
                $SignerCertificate.Thumbprint -eq $Script:SignerCertificate.Thumbprint
            }
            Should -Invoke Invoke-PGWYPKCS10Operation -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.ContainsKey('SignedData') -and [Convert]::ToBase64String($SignedData) -eq [Convert]::ToBase64String($Script:Signature)
            }
        }

        It 'signs with the client certificate when no -SignerCertificate is given' {
            $null = Get-PGWYCertificate -CertificateRequest $Script:Csr -ComputerName 'cm.contoso.com' -ClientCertificate $Script:ClientThumbprint

            Should -Invoke New-SignedCms -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                $SignerCertificate.Thumbprint -eq $Script:ClientCertificate.Thumbprint
            }
        }
    }

    Context 'failure' {

        It 'returns the response when no certificate was issued' {
            Mock Invoke-PGWYPKCS10Operation -ModuleName PSCertificateEnrollment { New-JsonResponse @{ msg = 'Request denied' } }

            $Result = Get-PGWYCertificate -CertificateRequest $Script:Csr -ComputerName 'cm.contoso.com' -ClientCertificate $Script:ClientThumbprint

            $Result.Content | Should -BeLike '*Request denied*'
            Should -Invoke New-SignedCms -ModuleName PSCertificateEnrollment -Times 0 -Exactly
        }

        It 'rejects a <Name> that is not a thumbprint' -ForEach @(
            @{ Name = 'ClientCertificate'; Parameters = @{ ClientCertificate = 'not-a-thumbprint' } }
            @{ Name = 'SignerCertificate'; Parameters = @{ ClientCertificate = 'C' * 40; SignerCertificate = 'ABC' } }
        ) {
            { Get-PGWYCertificate -CertificateRequest 'AQID' -ComputerName 'cm.contoso.com' @Parameters } |
                Should -Throw -ErrorId 'ParameterArgumentValidationError,Get-PGWYCertificate'
        }
    }
}
