BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-Asn1LengthOctets' {

    Context 'worked examples from the function''s own doc comment' {

        # HexStringLength is twice the Object/Byte Length (2 hex characters per byte)
        It 'encodes <ObjectLength> (short form)' -TestCases @(
            @{ ObjectLength = 127; Expected = '7F' }
        ) {
            InModuleScope PSCertificateEnrollment -Parameters @{ ObjectLength = $ObjectLength; Expected = $Expected } {
                Get-Asn1LengthOctets -HexStringLength ($ObjectLength * 2) | Should -Be $Expected
            }
        }

        It 'encodes <ObjectLength> (long form)' -TestCases @(
            @{ ObjectLength = 128;   Expected = '8180' }
            @{ ObjectLength = 255;   Expected = '81FF' }
            @{ ObjectLength = 256;   Expected = '820100' }
            @{ ObjectLength = 65535; Expected = '82FFFF' }
            @{ ObjectLength = 65536; Expected = '83010000' }
        ) {
            InModuleScope PSCertificateEnrollment -Parameters @{ ObjectLength = $ObjectLength; Expected = $Expected } {
                Get-Asn1LengthOctets -HexStringLength ($ObjectLength * 2) | Should -Be $Expected
            }
        }
    }

    Context 'invalid input' {

        It 'throws a clear error for an odd HexStringLength instead of a cryptic .NET formatting error' {
            InModuleScope PSCertificateEnrollment {
                { Get-Asn1LengthOctets -HexStringLength 7 } | Should -Throw '*even*'
            }
        }
    }
}
