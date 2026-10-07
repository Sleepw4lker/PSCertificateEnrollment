BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    $Script:Csr = "-----BEGIN NEW CERTIFICATE REQUEST-----`r`nMIIBAAAA`r`nBBBB`r`n-----END NEW CERTIFICATE REQUEST-----`r`n"
    $Script:MessageId = [guid]'11111111-2222-3333-4444-555555555555'

    # Runs Get-WSTEPResponse against a mocked server and returns the SOAP envelope it sent
    function Get-SentEnvelope {
        param([hashtable] $Parameters)

        $Script:SentBody = $null
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment {
            $Script:SentBody = $Body
            [PSCustomObject]@{ StatusCode = 200; Content = '<response/>' }
        }

        $null = Get-WSTEPResponse @Parameters
        [xml]$Script:SentBody
    }

    $Script:Ns = @{
        s    = 'http://www.w3.org/2003/05/soap-envelope'
        a    = 'http://www.w3.org/2005/08/addressing'
        wst  = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512'
        wsse = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
        auth = 'http://schemas.xmlsoap.org/ws/2006/12/authorization'
    }
    $Script:NsManager = [System.Xml.XmlNamespaceManager]::new([System.Xml.NameTable]::new())
    $Script:Ns.GetEnumerator() | ForEach-Object { $Script:NsManager.AddNamespace($_.Key, $_.Value) }
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-WSTEPResponse' {

    BeforeEach {
        Mock New-Guid -ModuleName PSCertificateEnrollment { $Script:MessageId }
    }

    It 'returns the raw response content' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { [PSCustomObject]@{ StatusCode = 200; Content = '<response/>' } }

        Get-WSTEPResponse -CertificateRequest $Script:Csr -ComputerName 'ces.contoso.com' | Should -Be '<response/>'
    }

    It 'POSTs SOAP with Windows authentication to the CES endpoint' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { [PSCustomObject]@{ StatusCode = 200; Content = '<response/>' } }

        $null = Get-WSTEPResponse -CertificateRequest $Script:Csr -ComputerName 'ces.contoso.com' -Suffix 'Contoso-CA_CES_Kerberos'

        Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://ces.contoso.com/Contoso-CA_CES_Kerberos/service.svc/CES' -and
            $Method -eq 'POST' -and
            $UseDefaultCredentials -and
            $Headers['Content-Type'] -eq 'application/soap+xml; charset=utf-8'
        }
    }

    It 'puts a non-default -Port into the URI' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { [PSCustomObject]@{ StatusCode = 200; Content = '<response/>' } }

        $null = Get-WSTEPResponse -CertificateRequest $Script:Csr -ComputerName 'ces.contoso.com' -Port 8443 -Suffix 'Contoso-CA_CES_Kerberos'

        Should -Invoke Invoke-WebRequest -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://ces.contoso.com:8443/Contoso-CA_CES_Kerberos/service.svc/CES'
        }
    }

    It 'addresses the envelope to the endpoint with a fresh message ID' {
        $Envelope = Get-SentEnvelope @{ CertificateRequest = $Script:Csr; ComputerName = 'ces.contoso.com'; Suffix = 'Contoso-CA_CES_Kerberos' }

        $Envelope.SelectSingleNode('/s:Envelope/s:Header/a:To', $Script:NsManager).InnerText |
            Should -Be 'https://ces.contoso.com/Contoso-CA_CES_Kerberos/service.svc/CES'
        $Envelope.SelectSingleNode('/s:Envelope/s:Header/a:MessageID', $Script:NsManager).InnerText |
            Should -Be "urn:uuid:$($Script:MessageId)"
        $Envelope.SelectSingleNode('/s:Envelope/s:Header/a:Action', $Script:NsManager).InnerText |
            Should -Be 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep'
    }

    It 'carries the request as a BinarySecurityToken without its PEM armor' {
        $Envelope = Get-SentEnvelope @{ CertificateRequest = $Script:Csr; ComputerName = 'ces.contoso.com' }

        $Envelope.SelectSingleNode('//wst:RequestSecurityToken/wsse:BinarySecurityToken', $Script:NsManager).InnerText |
            Should -BeExactly 'MIIBAAAABBBB'
    }

    It 'adds no CertificateTemplate context item without -CertificateTemplate' {
        $Envelope = Get-SentEnvelope @{ CertificateRequest = $Script:Csr; ComputerName = 'ces.contoso.com' }

        $Envelope.SelectNodes("//auth:ContextItem[@Name='CertificateTemplate']", $Script:NsManager).Count | Should -Be 0
        $Envelope.SelectNodes("//auth:ContextItem[@Name='ccm']", $Script:NsManager).Count | Should -Be 1
    }

    It 'adds the CertificateTemplate context item for -CertificateTemplate' {
        $Envelope = Get-SentEnvelope @{ CertificateRequest = $Script:Csr; ComputerName = 'ces.contoso.com'; CertificateTemplate = 'WebServer' }

        $Envelope.SelectSingleNode("//auth:ContextItem[@Name='CertificateTemplate']/auth:Value", $Script:NsManager).InnerText |
            Should -BeExactly 'WebServer'
    }

    It 'escapes XML special characters in the template name' {
        $Envelope = Get-SentEnvelope @{ CertificateRequest = $Script:Csr; ComputerName = 'ces.contoso.com'; CertificateTemplate = 'R&D <Web>' }

        $Envelope.SelectSingleNode("//auth:ContextItem[@Name='CertificateTemplate']/auth:Value", $Script:NsManager).InnerText |
            Should -BeExactly 'R&D <Web>'
    }

    It 'returns nothing for a response other than 200' {
        Mock Invoke-WebRequest -ModuleName PSCertificateEnrollment { [PSCustomObject]@{ StatusCode = 202; Content = '<response/>' } }

        Get-WSTEPResponse -CertificateRequest $Script:Csr -ComputerName 'ces.contoso.com' | Should -BeNullOrEmpty
    }
}
