BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    function New-MockNdesResponse {
        param(
            [int] $StatusCode = 200,
            [string] $Html = ''
        )
        [PSCustomObject]@{
            StatusCode       = $StatusCode
            RawContentStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::Unicode.GetBytes($Html))
        }
    }
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NDESOTP' {

    Context 'successful response' {

        It 'extracts the OTP from the HTML response body' {
            $Otp = 'ABCDEF0123456789'
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment {
                New-MockNdesResponse -StatusCode 200 -Html "<html><body>Password: $Otp</body></html>"
            }

            Get-NDESOTP -ComputerName 'ndes.contoso.com' | Should -Be $Otp
        }

        It 'uses https by default' {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment -ParameterFilter { $Uri -like 'https://*' } {
                New-MockNdesResponse -StatusCode 200 -Html '<html><body>ABCDEF0123456789</body></html>'
            }

            Get-NDESOTP -ComputerName 'ndes.contoso.com' | Should -Be 'ABCDEF0123456789'
            Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1
        }

        It 'uses http when -NoSSL is specified' {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment -ParameterFilter { $Uri -like 'http://*' } {
                New-MockNdesResponse -StatusCode 200 -Html '<html><body>ABCDEF0123456789</body></html>'
            }

            Get-NDESOTP -ComputerName 'ndes.contoso.com' -NoSSL -WarningAction SilentlyContinue | Should -Be 'ABCDEF0123456789'
            Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1
        }
    }

    Context 'error responses' {

        It 'errors when no OTP pattern is found in the HTML' {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment {
                New-MockNdesResponse -StatusCode 200 -Html '<html><body>no password here</body></html>'
            }

            { Get-NDESOTP -ComputerName 'ndes.contoso.com' -ErrorAction Stop } | Should -Throw
        }

        It 'errors on a non-200 HTTP status code' {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment {
                New-MockNdesResponse -StatusCode 404 -Html ''
            }

            { Get-NDESOTP -ComputerName 'ndes.contoso.com' -ErrorAction Stop } | Should -Throw
        }

        It 'surfaces a terminating error from Invoke-WebRequest' {
            Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { throw 'Connection refused' }

            { Get-NDESOTP -ComputerName 'ndes.contoso.com' -ErrorAction Stop } | Should -Throw
        }
    }
}
