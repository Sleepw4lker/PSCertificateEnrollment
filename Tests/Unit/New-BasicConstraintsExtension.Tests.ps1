BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-BasicConstraintsExtension' {

    It 'encodes an end entity as an empty SEQUENCE' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-BasicConstraintsExtension))) -replace '-'

            # 30 00                              SEQUENCE (BasicConstraints), cA DEFAULT FALSE omitted
            $Result | Should -Be '3000'
        }
    }

    It 'encodes a CA without a path length constraint' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-BasicConstraintsExtension -IsCA))) -replace '-'

            # 30 03
            #   01 01 FF                         BOOLEAN TRUE (cA)
            $Result | Should -Be '30030101FF'
        }
    }

    It 'encodes a CA with path length <PathLength>' -ForEach @(
        @{ PathLength = 0; Expected = '30060101FF020100' }
        @{ PathLength = 3; Expected = '30060101FF020103' }
    ) {
        InModuleScope PSCertificateEnrollment -Parameters @{ PathLength = $PathLength; Expected = $Expected } {
            $Bytes = [Convert]::FromBase64String((New-BasicConstraintsExtension -IsCA -PathLength $PathLength))

            # 30 06
            #   01 01 FF                         BOOLEAN TRUE (cA)
            #   02 01 <n>                        INTEGER pathLenConstraint
            [BitConverter]::ToString($Bytes) -replace '-' | Should -Be $Expected

            $Decoded = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                [System.Security.Cryptography.AsnEncodedData]::new('2.5.29.19', $Bytes), $true)
            $Decoded.CertificateAuthority | Should -BeTrue
            $Decoded.HasPathLengthConstraint | Should -BeTrue
            $Decoded.PathLengthConstraint | Should -Be $PathLength
        }
    }
}
