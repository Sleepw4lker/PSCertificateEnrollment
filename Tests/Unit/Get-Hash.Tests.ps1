BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-Hash' {

    Context 'known-answer vectors for the ASCII bytes of "abc"' {

        It 'computes the correct SHA1 hash (default algorithm)' {
            InModuleScope PSCertificateEnrollment {
                $Bytes = [System.Text.Encoding]::ASCII.GetBytes('abc')
                Get-Hash -Bytes $Bytes | Should -Be 'A9993E364706816ABA3E25717850C26C9CD0D89D'
            }
        }

        It 'computes the correct SHA256 hash' {
            InModuleScope PSCertificateEnrollment {
                $Bytes = [System.Text.Encoding]::ASCII.GetBytes('abc')
                Get-Hash -Bytes $Bytes -HashAlgorithm SHA256 |
                    Should -Be 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'
            }
        }
    }

    It 'returns a hex string with no separators' {
        InModuleScope PSCertificateEnrollment {
            Get-Hash -Bytes ([byte[]](1, 2, 3)) | Should -Match '^[0-9A-F]+$'
        }
    }
}
