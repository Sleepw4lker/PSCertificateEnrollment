BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-TemplateExtension' {

    It 'encodes the template OID with the default version 100.1' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-TemplateExtension -ObjectIdentifier '1.3.6.1.4.1.311.21.8.1.2'))) -replace '-'

            # 30 13                              SEQUENCE (CertificateTemplate)
            #   06 0B 2B06010401823715080102     OID 1.3.6.1.4.1.311.21.8.1.2
            #   02 01 64                         INTEGER 100 (templateMajorVersion)
            #   02 01 01                         INTEGER 1 (templateMinorVersion)
            $Result | Should -Be '3013060B2B06010401823715080102020164020101'
        }
    }

    It 'omits the optional minor version when it is 0' {
        InModuleScope PSCertificateEnrollment {
            $Base64 = New-TemplateExtension -ObjectIdentifier '1.3.6.1.4.1.311.21.8.1.2' -MajorVersion 5 -MinorVersion 0
            $Result = [BitConverter]::ToString([Convert]::FromBase64String($Base64)) -replace '-'

            # 30 10
            #   06 0B 2B06010401823715080102
            #   02 01 05                         INTEGER 5 (templateMinorVersion is OPTIONAL, CertEnroll leaves out 0)
            $Result | Should -Be '3010060B2B06010401823715080102020105'
        }
    }

    It 'throws for a string that is not an OID' {
        InModuleScope PSCertificateEnrollment {
            { New-TemplateExtension -ObjectIdentifier 'not-an-oid' } | Should -Throw
        }
    }
}
