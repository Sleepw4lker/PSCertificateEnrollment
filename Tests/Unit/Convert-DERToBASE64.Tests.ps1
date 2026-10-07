BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Convert-DERToBASE64' {

    It 'converts an empty SEQUENCE (30 00) to Base64' {
        InModuleScope PSCertificateEnrollment {
            Convert-DERToBASE64 -String '3000' | Should -Be 'MAA='
        }
    }

    It 'accepts lower-case hex' {
        InModuleScope PSCertificateEnrollment {
            Convert-DERToBASE64 -String '0a0bff' | Should -Be ([Convert]::ToBase64String([byte[]](0x0A, 0x0B, 0xFF)))
        }
    }

    It 'round-trips the output of Convert-StringToDER' {
        InModuleScope PSCertificateEnrollment {
            # 04 03 41 42 43 - OCTET STRING "ABC"
            $Der = Convert-StringToDER -IdentifierOctets '04' -ContentOctets '414243'
            [Convert]::FromBase64String((Convert-DERToBASE64 -String $Der)) | Should -Be ([byte[]](0x04, 0x03, 0x41, 0x42, 0x43))
        }
    }

    # Rejected at parameter binding, rather than failing halfway through the conversion
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'a hex string of odd length'; String = '300' }
        @{ Case = 'non-hex characters'; String = '30zz' }
    ) {
        InModuleScope PSCertificateEnrollment -Parameters @{ String = $String } {
            param($String)
            { Convert-DERToBASE64 -String $String } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Convert-DERToBASE64'
        }
    }
}
