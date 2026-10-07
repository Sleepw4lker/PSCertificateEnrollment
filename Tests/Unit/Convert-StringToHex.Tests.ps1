BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Convert-StringToHex' {

    Context 'ASCII input' {

        It 'converts each character to its 2-digit hex ASCII value' {
            InModuleScope PSCertificateEnrollment {
                Convert-StringToHex -String 'AB' | Should -Be '4142'
            }
        }

        It 'converts a digit string' {
            InModuleScope PSCertificateEnrollment {
                Convert-StringToHex -String '0' | Should -Be '30'
            }
        }

        It 'converts a space character' {
            InModuleScope PSCertificateEnrollment {
                Convert-StringToHex -String ' ' | Should -Be '20'
            }
        }
    }

    Context 'non-ASCII input' {

        It 'throws instead of silently emitting a malformed (variable-width) hex string' {
            InModuleScope PSCertificateEnrollment {
                # U+20AC (EURO SIGN) is above U+00FF and cannot be represented as a fixed 2-digit hex value.
                # Built with [char] rather than "`u{20AC}", which Windows PowerShell 5.1 doesn't support.
                { Convert-StringToHex -String "price: $([char]0x20AC)5" } | Should -Throw '*non-ASCII*'
            }
        }
    }

    Context 'invalid input' {

        It 'throws for an empty string' {
            InModuleScope PSCertificateEnrollment {
                { Convert-StringToHex -String '' } | Should -Throw
            }
        }
    }
}
