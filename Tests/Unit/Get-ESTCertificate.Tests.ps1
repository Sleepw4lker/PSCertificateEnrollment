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

    # What an RFC 7030 server answers to /simpleenroll: a certs-only PKCS#7 with the issued certificate
    function New-MockEnrollResponse {
        param(
            [object] $ContentType = 'application/pkcs7-mime; smime-type=certs-only',
            [int] $StatusCode = 200
        )
        $Collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        [void]$Collection.Add($Script:IssuedCertificate)
        $Base64 = [Convert]::ToBase64String($Collection.Export('Pkcs7'), [Base64FormattingOptions]::InsertLineBreaks)

        [PSCustomObject]@{
            StatusCode = $StatusCode
            Headers    = @{ 'Content-Type' = $ContentType }
            Content    = [System.Text.Encoding]::ASCII.GetBytes($Base64)
        }
    }

    $Script:IssuedCertificate = New-TestCertificate -Subject 'CN=PesterTest Issued'

    # The renewal certificate must look like it came from the Cert: drive. The note property is
    # kept with the certificate object itself, so the certificate never has to touch a store.
    $Script:RenewalCertificate = New-TestCertificate -Subject 'CN=PesterTest Renewal'
    $Script:RenewalCertificate | Add-Member -NotePropertyName PSParentPath -NotePropertyValue 'Microsoft.PowerShell.Security\Certificate::CurrentUser\My'

    $Script:Csr = "-----BEGIN NEW CERTIFICATE REQUEST-----`r`nMIIBAAAA`r`nBBBB`r`n-----END NEW CERTIFICATE REQUEST-----`r`n"
}

AfterAll {
    $Script:IssuedCertificate, $Script:RenewalCertificate | ForEach-Object { $_.Dispose() }
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-ESTCertificate' {

    BeforeEach {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockEnrollResponse }
    }

    Context 'enrollment' {

        It 'returns the issued certificate' {
            (Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com').Thumbprint |
                Should -Be $Script:IssuedCertificate.Thumbprint
        }

        It 'POSTs the request to /simpleenroll without a client certificate' {
            $null = Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com' -Port 8443

            Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://est.contoso.com:8443/.well-known/est/simpleenroll' -and
                $Method -eq 'POST' -and
                -not $PesterBoundParameters.ContainsKey('Certificate')
            }
        }

        It 'sends the Base64 request without its PEM armor as application/pkcs10' {
            $null = Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com'

            Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                $Body -eq 'MIIBAAAABBBB' -and
                $Headers['Content-Type'] -eq 'application/pkcs10' -and
                $Headers['Content-Transfer-Encoding'] -eq 'base64'
            }
        }

        It 'sends no Authorization header without -Credential' {
            $null = Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com'

            Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                -not $Headers.ContainsKey('Authorization')
            }
        }

        It 'sends HTTP Basic authentication for -Credential' {
            $Credential = [PSCredential]::new('user', (ConvertTo-SecureString -String 'p@ss' -AsPlainText -Force))

            $null = Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com' -Credential $Credential

            # "user:p@ss"
            Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                $Headers['Authorization'] -eq 'Basic dXNlcjpwQHNz'
            }
        }

        It 'accepts a request piped in' {
            ($Script:Csr | Get-ESTCertificate -ComputerName 'est.contoso.com').Thumbprint |
                Should -Be $Script:IssuedCertificate.Thumbprint
        }
    }

    Context 'renewal' {

        It 'POSTs to /simplereenroll and authenticates with the renewal certificate' {
            $null = Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com' -RenewalCertificate $Script:RenewalCertificate

            Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://est.contoso.com:443/.well-known/est/simplereenroll' -and
                $Certificate.Thumbprint -eq $Script:RenewalCertificate.Thumbprint
            }
        }

        It 'rejects a renewal certificate without a private key' {
            $PublicOnly = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Script:RenewalCertificate.RawData)

            { Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com' -RenewalCertificate $PublicOnly } |
                Should -Throw -ErrorId 'ParameterArgumentValidationError,Get-ESTCertificate'
        }
    }

    Context 'response handling' {

        # Windows PowerShell returns header values as strings, PowerShell 7 as string arrays
        It 'accepts the Content-Type header as a string array' {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockEnrollResponse -ContentType @('application/pkcs7-mime; smime-type=certs-only') }

            (Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com' -ErrorAction Stop).Thumbprint |
                Should -Be $Script:IssuedCertificate.Thumbprint
        }

        It 'accepts a Content-Type of <Case>' -ForEach @(
            @{ Case = 'the parameter written without a space'; ContentType = 'application/pkcs7-mime;smime-type=certs-only' }
            @{ Case = 'the media type alone'; ContentType = 'application/pkcs7-mime' }
        ) {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockEnrollResponse -ContentType $ContentType }

            (Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com' -ErrorAction Stop).Thumbprint |
                Should -Be $Script:IssuedCertificate.Thumbprint
        }

        It 'writes an error for a response that is not application/pkcs7-mime' {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockEnrollResponse -ContentType 'text/html' }

            { Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com' -ErrorAction Stop } |
                Should -Throw '*text/html*not compliant to RFC 7030*'
        }

        # RFC 7030 4.2.3: 202 means the request is pending manual approval
        It 'passes a response other than 200 through' {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockEnrollResponse -StatusCode 202 }

            (Get-ESTCertificate -CertificateRequest $Script:Csr -ComputerName 'est.contoso.com').StatusCode | Should -Be 202
        }
    }
}
