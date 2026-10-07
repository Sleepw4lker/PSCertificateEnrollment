BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-SidExtension' {

    It 'wraps the SID string in an OtherName with OID 1.3.6.1.4.1.311.25.2.1' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-SidExtension -Sid 'S-1-5-21-1-2-3-500'))) -replace '-'

            # 30 24                              SEQUENCE
            #   A0 22                            [0] otherName
            #     06 0A 2B060104018237190201     OID 1.3.6.1.4.1.311.25.2.1
            #     A0 14                          [0] value
            #       04 12 532D312D352D32312D312D322D332D353030  OCTET STRING "S-1-5-21-1-2-3-500"
            $Result | Should -Be '3024A022060A2B060104018237190201A0140412532D312D352D32312D312D322D332D353030'
        }
    }

    It 'rejects an empty SID' {
        InModuleScope PSCertificateEnrollment {
            { New-SidExtension -Sid '' } | Should -Throw
        }
    }
}
