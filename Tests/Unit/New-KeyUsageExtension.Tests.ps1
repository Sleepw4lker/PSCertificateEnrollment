BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-KeyUsageExtension' {

    It 'encodes DigitalSignature as a single-bit BIT STRING' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-KeyUsageExtension -KeyUsage DigitalSignature))) -replace '-'

            # 03 02 07 80                        BIT STRING, 7 unused bits, bit 0 (digitalSignature)
            $Result | Should -Be '03020780'
        }
    }

    It 'combines DigitalSignature and KeyEncipherment' {
        InModuleScope PSCertificateEnrollment {
            $Bytes = [Convert]::FromBase64String((New-KeyUsageExtension -KeyUsage DigitalSignature, KeyEncipherment))

            # 03 02 05 A0                        BIT STRING, 5 unused bits, bits 0 and 2
            [BitConverter]::ToString($Bytes) -replace '-' | Should -Be '030205A0'

            $Decoded = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.AsnEncodedData]::new('2.5.29.15', $Bytes), $false)
            $Decoded.KeyUsages | Should -Be ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyEncipherment')
        }
    }

    It 'encodes the CA case KeyCertSign and CrlSign' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-KeyUsageExtension -KeyUsage KeyCertSign, CrlSign))) -replace '-'

            # 03 02 01 06                        BIT STRING, 1 unused bit, bits 5 and 6
            $Result | Should -Be '03020106'
        }
    }

    It 'rejects a value outside the ValidateSet' {
        InModuleScope PSCertificateEnrollment {
            { New-KeyUsageExtension -KeyUsage 'Bogus' } | Should -Throw
        }
    }
}
