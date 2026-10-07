BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    $Script:MessageId = [guid]'11111111-2222-3333-4444-555555555555'

    $Script:NsManager = [System.Xml.XmlNamespaceManager]::new([System.Xml.NameTable]::new())
    $Script:NsManager.AddNamespace('s', 'http://www.w3.org/2003/05/soap-envelope')
    $Script:NsManager.AddNamespace('a', 'http://www.w3.org/2005/08/addressing')
    $Script:NsManager.AddNamespace('ep', 'http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy')
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-XCEPEnrollmentPolicy' {

    BeforeEach {
        Mock New-Guid -ModuleName PSCertificateEnrollment { $Script:MessageId }

        $Script:SentBody = $null
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment {
            $Script:SentBody = $Body
            [PSCustomObject]@{ StatusCode = 200; Content = '<policies/>' }
        }
    }

    It 'returns the raw response content' {
        Get-XCEPEnrollmentPolicy -ComputerName 'cep.contoso.com' | Should -Be '<policies/>'
    }

    It 'POSTs SOAP with Windows authentication to the default Kerberos endpoint' {
        $null = Get-XCEPEnrollmentPolicy -ComputerName 'cep.contoso.com'

        Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://cep.contoso.com:443/ADPolicyProvider_CEP_Kerberos/service.svc/CEP/' -and
            $Method -eq 'POST' -and
            $UseDefaultCredentials -and
            $Headers['Content-Type'] -eq 'application/soap+xml; charset=utf-8'
        }
    }

    It 'builds the URI from -Port and -Suffix' {
        $null = Get-XCEPEnrollmentPolicy -ComputerName 'cep.contoso.com' -Port 8443 -Suffix 'ADPolicyProvider_CEP_UsernamePassword'

        Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://cep.contoso.com:8443/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP/'
        }
    }

    It 'sends a GetPolicies request addressed to the endpoint' {
        $null = Get-XCEPEnrollmentPolicy -ComputerName 'cep.contoso.com'
        $Envelope = [xml]$Script:SentBody

        $Envelope.SelectSingleNode('/s:Envelope/s:Header/a:Action', $Script:NsManager).InnerText |
            Should -Be 'http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies'
        $Envelope.SelectSingleNode('/s:Envelope/s:Header/a:To', $Script:NsManager).InnerText |
            Should -Be 'https://cep.contoso.com:443/ADPolicyProvider_CEP_Kerberos/service.svc/CEP/'
        $Envelope.SelectSingleNode('/s:Envelope/s:Header/a:MessageID', $Script:NsManager).InnerText |
            Should -Be "urn:uuid:$($Script:MessageId)"
        $Envelope.SelectNodes('/s:Envelope/s:Body/ep:GetPolicies', $Script:NsManager).Count | Should -Be 1
    }

    It 'returns nothing for a response other than 200' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { [PSCustomObject]@{ StatusCode = 202; Content = '<policies/>' } }

        Get-XCEPEnrollmentPolicy -ComputerName 'cep.contoso.com' | Should -BeNullOrEmpty
    }

    It 'rejects port <Port>' -ForEach @(@{ Port = 0 }, @{ Port = 65536 }) {
        { Get-XCEPEnrollmentPolicy -ComputerName 'cep.contoso.com' -Port $Port } |
            Should -Throw -ErrorId 'ParameterArgumentValidationError,Get-XCEPEnrollmentPolicy'
    }
}
