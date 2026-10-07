BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'ConvertFrom-Base64ToPem' {

    It 'wraps the Base64 in 64-character lines between the certificate armor' {
        InModuleScope PSCertificateEnrollment {
            $Lines = (ConvertFrom-Base64ToPem -String ('A' * 150)) -split "`n"

            $Lines[0] | Should -BeExactly '-----BEGIN CERTIFICATE-----'
            $Lines[-1] | Should -BeExactly '-----END CERTIFICATE-----'
            $Lines[1..3] | ForEach-Object Length | Should -Be @(64, 64, 22)
        }
    }

    It 'does not add an empty line when the length is a multiple of 64' {
        InModuleScope PSCertificateEnrollment {
            (ConvertFrom-Base64ToPem -String ('A' * 128)) -split "`n" | Should -HaveCount 4
        }
    }

    It 'keeps a short input on one line' {
        InModuleScope PSCertificateEnrollment {
            ConvertFrom-Base64ToPem -String 'MAA=' | Should -BeExactly "-----BEGIN CERTIFICATE-----`nMAA=`n-----END CERTIFICATE-----"
        }
    }

    It 'round-trips through ConvertFrom-PemToBase64' {
        InModuleScope PSCertificateEnrollment {
            $Base64 = [Convert]::ToBase64String([byte[]](0..199))
            ConvertFrom-PemToBase64 -String (ConvertFrom-Base64ToPem -String $Base64) | Should -BeExactly $Base64
        }
    }
}
