BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'ConvertFrom-PemToBase64' {

    It 'strips the armor and line breaks of a <Case>' -ForEach @(
        @{ Case = 'certificate with CRLF line breaks'; Pem = "-----BEGIN CERTIFICATE-----`r`nMIIB`r`nAAAA`r`n-----END CERTIFICATE-----`r`n" }
        @{ Case = 'certificate with LF line breaks'; Pem = "-----BEGIN CERTIFICATE-----`nMIIB`nAAAA`n-----END CERTIFICATE-----" }
        @{ Case = 'certificate request'; Pem = "-----BEGIN NEW CERTIFICATE REQUEST-----`r`nMIIB`r`nAAAA`r`n-----END NEW CERTIFICATE REQUEST-----" }
    ) {
        InModuleScope PSCertificateEnrollment -Parameters @{ Pem = $Pem } {
            param($Pem)
            ConvertFrom-PemToBase64 -String $Pem | Should -BeExactly 'MIIBAAAA'
        }
    }

    It 'strips the armor and whitespace of a <Case>' -ForEach @(
        @{ Case = 'PEM on a single line'; Pem = '-----BEGIN CERTIFICATE-----MIIBAAAA-----END CERTIFICATE-----' }
        @{ Case = 'PEM with indented lines'; Pem = "-----BEGIN CERTIFICATE-----`n  MIIB`n`tAAAA `n-----END CERTIFICATE-----" }
    ) {
        InModuleScope PSCertificateEnrollment -Parameters @{ Pem = $Pem } {
            param($Pem)
            ConvertFrom-PemToBase64 -String $Pem | Should -BeExactly 'MIIBAAAA'
        }
    }

    It 'passes plain Base64 through unchanged' {
        InModuleScope PSCertificateEnrollment {
            ConvertFrom-PemToBase64 -String 'MIIBAAAA+/==' | Should -BeExactly 'MIIBAAAA+/=='
        }
    }
}
