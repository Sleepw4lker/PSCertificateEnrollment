BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-AiaExtension' {

    It 'encodes a non-OCSP URL as a caIssuers access description' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-AiaExtension -Url 'http://a/b.crt'))) -replace '-'

            # 30 1C                              SEQUENCE (AuthorityInfoAccessSyntax)
            #   30 1A                            SEQUENCE (AccessDescription)
            #     06 08 2B06010505073002         OID 1.3.6.1.5.5.7.48.2 (caIssuers)
            #     86 0E 687474703A2F2F612F622E637274  [6] uniformResourceIdentifier "http://a/b.crt"
            $Result | Should -Be '301C301A06082B06010505073002860E687474703A2F2F612F622E637274'
        }
    }

    It 'encodes a URL containing /ocsp as an OCSP access description' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-AiaExtension -Url 'http://a/ocsp'))) -replace '-'

            # 30 1B
            #   30 19
            #     06 08 2B06010505073001         OID 1.3.6.1.5.5.7.48.1 (ocsp)
            #     86 0D 687474703A2F2F612F6F637370  "http://a/ocsp"
            $Result | Should -Be '301B301906082B06010505073001860D687474703A2F2F612F6F637370'
        }
    }

    It 'detects /OCSP case-insensitively' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-AiaExtension -Url 'http://a/OCSP'))) -replace '-'

            $Result | Should -Be '301B301906082B06010505073001860D687474703A2F2F612F4F435350'
        }
    }

    It 'keeps multiple URLs in input order within one outer SEQUENCE' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-AiaExtension -Url 'http://a/b.crt', 'http://a/ocsp'))) -replace '-'

            # 30 37 <caIssuers AccessDescription> <ocsp AccessDescription>
            $Result | Should -Be ('3037' +
                '301A06082B06010505073002860E687474703A2F2F612F622E637274' +
                '301906082B06010505073001860D687474703A2F2F612F6F637370')
        }
    }

    It 'rejects an empty URL list' {
        InModuleScope PSCertificateEnrollment {
            { New-AiaExtension -Url @() } | Should -Throw
        }
    }
}
