BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Convert-StringToCertificateSerialNumber' {

    It 'converts an even-length hex serial number to Base64' {
        InModuleScope PSCertificateEnrollment {
            Convert-StringToCertificateSerialNumber -SerialNumber '0102AB' | Should -Be ([Convert]::ToBase64String([byte[]](0x01, 0x02, 0xAB)))
        }
    }

    It 'pads an odd-length serial number with a leading zero' {
        InModuleScope PSCertificateEnrollment {
            # "1" -> 01
            Convert-StringToCertificateSerialNumber -SerialNumber '1' | Should -Be 'AQ=='
        }
    }

    It 'keeps leading zero bytes' {
        InModuleScope PSCertificateEnrollment {
            # 00 FF
            Convert-StringToCertificateSerialNumber -SerialNumber '00FF' | Should -Be 'AP8='
        }
    }

    It 'accepts lower-case hex' {
        InModuleScope PSCertificateEnrollment {
            Convert-StringToCertificateSerialNumber -SerialNumber 'abcd' | Should -Be 'q80='
        }
    }

    It 'accepts 100 hex characters' {
        InModuleScope PSCertificateEnrollment {
            [Convert]::FromBase64String((Convert-StringToCertificateSerialNumber -SerialNumber ('A' * 100))).Length | Should -Be 50
        }
    }

    It 'rejects <Case>' -ForEach @(
        @{ Case = 'more than 100 hex characters'; SerialNumber = 'A' * 101 }
        @{ Case = 'non-hex characters'; SerialNumber = 'xyz' }
        @{ Case = 'an empty string'; SerialNumber = '' }
    ) {
        InModuleScope PSCertificateEnrollment -Parameters @{ SerialNumber = $SerialNumber } {
            param($SerialNumber)
            { Convert-StringToCertificateSerialNumber -SerialNumber $SerialNumber } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Convert-StringToCertificateSerialNumber'
        }
    }

    # Checked through the metadata: calling it without the parameter would prompt in an interactive session
    It 'makes SerialNumber mandatory' {
        InModuleScope PSCertificateEnrollment {
            (Get-Command Convert-StringToCertificateSerialNumber).Parameters['SerialNumber'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                    ForEach-Object Mandatory | Should -BeTrue
        }
    }
}
