BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Convert-StringToDER' {

    It 'assembles Identifier + Length + Content octets for a short (3 byte) value' {
        InModuleScope PSCertificateEnrollment {
            # "414243" is the hex encoding of "ABC" (3 bytes) -> short-form length "03"
            Convert-StringToDER -IdentifierOctets '30' -ContentOctets '414243' | Should -Be '3003414243'
        }
    }

    It 'uses long-form length encoding once content exceeds 127 bytes' {
        InModuleScope PSCertificateEnrollment {
            # 128 bytes of content, encoded as 256 hex characters -> long-form length "8180"
            $ContentOctets = '41' * 128
            $Result = Convert-StringToDER -IdentifierOctets '30' -ContentOctets $ContentOctets
            $Result | Should -Be "30$('8180')$ContentOctets"
        }
    }
}
