BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-CdpExtension' {

    It 'encodes a single URL as one DistributionPoint' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-CdpExtension -Url 'http://a/b.crl'))) -replace '-'

            # 30 16                              SEQUENCE (CRLDistributionPoints)
            #   30 14                            SEQUENCE (DistributionPoint)
            #     A0 12                          [0] distributionPoint
            #       A0 10                        [0] fullName
            #         86 0E 687474703A2F2F612F622E63726C  [6] uniformResourceIdentifier "http://a/b.crl"
            $Result | Should -Be '30163014A012A010860E687474703A2F2F612F622E63726C'
        }
    }

    It 'places multiple URLs under the fullName of a single DistributionPoint' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-CdpExtension -Url 'http://a/b.crl', 'http://c/d.crl'))) -replace '-'

            $Result | Should -Be ('30263024A022A020' +
                '860E687474703A2F2F612F622E63726C' +
                '860E687474703A2F2F632F642E63726C')
        }
    }

    It 'rejects an empty URL list' {
        InModuleScope PSCertificateEnrollment {
            { New-CdpExtension -Url @() } | Should -Throw
        }
    }
}
