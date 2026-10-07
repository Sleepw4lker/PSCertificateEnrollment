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

    # What an RFC 7030 server answers to /cacerts: a certs-only PKCS#7, Base64 with line breaks
    function New-MockCaCertsResponse {
        param(
            [object] $ContentType = 'application/pkcs7-mime',
            [int] $StatusCode = 200
        )
        $Collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $Script:CaCertificates | ForEach-Object { [void]$Collection.Add($_) }
        $Base64 = [Convert]::ToBase64String($Collection.Export('Pkcs7'), [Base64FormattingOptions]::InsertLineBreaks)

        [PSCustomObject]@{
            StatusCode = $StatusCode
            Headers    = @{ 'Content-Type' = $ContentType }
            Content    = [System.Text.Encoding]::ASCII.GetBytes($Base64)
        }
    }

    $Script:CaCertificates = @(
        New-TestCertificate -Subject 'CN=PesterTest Root CA'
        New-TestCertificate -Subject 'CN=PesterTest Issuing CA'
    )
}

AfterAll {
    $Script:CaCertificates | ForEach-Object { $_.Dispose() }
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-ESTCACertificates' {

    It 'returns the certificates of the certs-only response' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockCaCertsResponse }

        $Result = Get-ESTCACertificates -ComputerName 'est.contoso.com'

        @($Result).Count | Should -Be 2
        $Result.Thumbprint | Sort-Object | Should -Be ($Script:CaCertificates.Thumbprint | Sort-Object)
    }

    It 'calls /cacerts below the default well-known path' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockCaCertsResponse }

        $null = Get-ESTCACertificates -ComputerName 'est.contoso.com'

        Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://est.contoso.com:443/.well-known/est/cacerts'
        }
    }

    It 'builds the URI from -Port and -Suffix' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockCaCertsResponse }

        $null = Get-ESTCACertificates -ComputerName 'est.contoso.com' -Port 8443 -Suffix '.well-known/est/arbitraryLabel'

        Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://est.contoso.com:8443/.well-known/est/arbitraryLabel/cacerts'
        }
    }

    # Windows PowerShell returns header values as strings, PowerShell 7 as string arrays
    It 'accepts the Content-Type header as a string array' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockCaCertsResponse -ContentType @('application/pkcs7-mime') }

        @(Get-ESTCACertificates -ComputerName 'est.contoso.com').Count | Should -Be 2
    }

    It 'accepts the media type in upper case' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockCaCertsResponse -ContentType 'Application/PKCS7-MIME' }

        @(Get-ESTCACertificates -ComputerName 'est.contoso.com' -ErrorAction Stop).Count | Should -Be 2
    }

    It 'accepts a Content-Type with the <Case>' -ForEach @(
        @{ Case = 'certs-only smime-type parameter'; ContentType = 'application/pkcs7-mime; smime-type=certs-only' }
        @{ Case = 'parameter written without a space'; ContentType = 'application/pkcs7-mime;smime-type=certs-only' }
    ) {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockCaCertsResponse -ContentType $ContentType }

        @(Get-ESTCACertificates -ComputerName 'est.contoso.com' -ErrorAction Stop).Count | Should -Be 2
    }

    It 'writes an error for a response that is not application/pkcs7-mime' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockCaCertsResponse -ContentType 'text/html' }

        { Get-ESTCACertificates -ComputerName 'est.contoso.com' -ErrorAction Stop } | Should -Throw '*text/html*not compliant to RFC 7030*'
    }

    It 'passes a response other than 200 through' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { New-MockCaCertsResponse -StatusCode 204 }

        (Get-ESTCACertificates -ComputerName 'est.contoso.com').StatusCode | Should -Be 204
    }

    It 'lets a failed request surface' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { throw 'Unable to connect to the remote server' }

        { Get-ESTCACertificates -ComputerName 'est.contoso.com' -ErrorAction Stop } | Should -Throw '*Unable to connect*'
    }
}
