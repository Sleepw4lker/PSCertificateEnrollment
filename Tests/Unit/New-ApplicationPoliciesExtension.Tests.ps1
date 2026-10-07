BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-ApplicationPoliciesExtension' {

    It 'encodes a single policy as a SEQUENCE of one PolicyInformation' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-ApplicationPoliciesExtension -ApplicationPolicies ServerAuthentication))) -replace '-'

            # 30 0C                              SEQUENCE (CertificatePolicies)
            #   30 0A                            SEQUENCE (PolicyInformation)
            #     06 08 2B06010505070301         OID 1.3.6.1.5.5.7.3.1 (serverAuth)
            $Result | Should -Be '300C300A06082B06010505070301'
        }
    }

    It 'sorts by name and removes duplicates' {
        InModuleScope PSCertificateEnrollment {
            $Base64 = New-ApplicationPoliciesExtension -ApplicationPolicies ServerAuthentication, ClientAuthentication, ClientAuthentication
            $Result = [BitConverter]::ToString([Convert]::FromBase64String($Base64)) -replace '-'

            # 30 18 <clientAuth PolicyInformation> <serverAuth PolicyInformation>
            $Result | Should -Be '3018300A06082B06010505070302300A06082B06010505070301'
        }
    }

    It 'treats differently cased names as duplicates' {
        InModuleScope PSCertificateEnrollment {
            $Base64 = New-ApplicationPoliciesExtension -ApplicationPolicies ServerAuthentication, serverauthentication
            $Result = [BitConverter]::ToString([Convert]::FromBase64String($Base64)) -replace '-'

            $Result | Should -Be '300C300A06082B06010505070301'
        }
    }

    It 'accepts the ApplicationPolicy alias' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-ApplicationPoliciesExtension -ApplicationPolicy ServerAuthentication))) -replace '-'

            $Result | Should -Be '300C300A06082B06010505070301'
        }
    }

    It 'rejects a value outside the ValidateSet' {
        InModuleScope PSCertificateEnrollment {
            { New-ApplicationPoliciesExtension -ApplicationPolicies 'Bogus' } | Should -Throw
        }
    }
}
