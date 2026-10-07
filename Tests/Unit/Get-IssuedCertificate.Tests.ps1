BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    # Stand-in for the CertificateAuthority.Request COM object: records every call, answers with
    # the given disposition. No CA is ever contacted.
    function New-FakeCaRequest {
        param([int] $Disposition = 3, [int] $LastStatus = 0)

        $Fake = [PSCustomObject]@{
            Disposition = $Disposition
            LastStatus  = $LastStatus
            Calls       = [System.Collections.Generic.List[object]]::new()
        }
        $Fake | Add-Member -MemberType ScriptMethod -Name Submit -Value {
            param($Flags, $Request, $Attributes, $Config)
            $this.Calls.Add([PSCustomObject]@{ Method = 'Submit'; Flags = $Flags; Request = $Request; Attributes = $Attributes; Config = $Config })
            $this.Disposition
        }
        $Fake | Add-Member -MemberType ScriptMethod -Name RetrievePending -Value {
            param($RequestId, $Config)
            $this.Calls.Add([PSCustomObject]@{ Method = 'RetrievePending'; RequestId = $RequestId; Config = $Config })
            $this.Disposition
        }
        $Fake | Add-Member -MemberType ScriptMethod -Name SetCredential -Value {
            param($Window, $AuthType, $Name, $Secret)
            $this.Calls.Add([PSCustomObject]@{ Method = 'SetCredential'; AuthType = $AuthType; Name = $Name; Secret = $Secret })
        }
        $Fake | Add-Member -MemberType ScriptMethod -Name GetLastStatus -Value { $this.LastStatus }
        $Fake | Add-Member -MemberType ScriptMethod -Name GetRequestId -Value { 42 }
        $Fake | Add-Member -MemberType ScriptMethod -Name GetCertificate -Value {
            param($Flags)
            $Base64 = [Convert]::ToBase64String($Script:IssuedCertificate.RawData)
            if ($Flags -eq 0) { "-----BEGIN CERTIFICATE-----`r`n$Base64`r`n-----END CERTIFICATE-----`r`n" } else { $Base64 }
        }
        $Fake
    }

    $Key = [System.Security.Cryptography.RSA]::Create(2048)
    $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=PesterTest Issued', $Key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $Script:IssuedCertificate = $Request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))

    $Script:Csr = "-----BEGIN NEW CERTIFICATE REQUEST-----`r`nAQID`r`n-----END NEW CERTIFICATE REQUEST-----`r`n"
    $Script:RpcConfig = 'ca.contoso.com\Contoso Issuing CA'
}

AfterAll {
    $Script:IssuedCertificate.Dispose()
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-IssuedCertificate' {

    BeforeEach {
        $Script:Fake = New-FakeCaRequest
        Mock New-Object -ModuleName PSCertificateEnrollment -ParameterFilter { $ComObject -eq 'CertificateAuthority.Request' } { $Script:Fake }
        # Every other New-Object call (e.g. the Win32Exception for the status message) stays real
        Mock New-Object -ModuleName PSCertificateEnrollment { Microsoft.PowerShell.Utility\New-Object @PesterBoundParameters }
        # The fake is no COM object, so it cannot go through the real release
        Mock Unregister-ComObject -ModuleName PSCertificateEnrollment -RemoveParameterType ComObject {}
    }

    Context 'submission over RPC/DCOM' {

        It 'returns the issued certificate' {
            $Result = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString $Script:RpcConfig

            $Result.Disposition | Should -Be 3
            $Result.Result | Should -Be 'Certificate was issued'
            $Result.RequestId | Should -Be 42
            $Result.Certificate.Thumbprint | Should -Be $Script:IssuedCertificate.Thumbprint
            $Result.RawCertificate | Should -BeLike '-----BEGIN CERTIFICATE-----*'
        }

        It 'submits the request to the CA with no attributes' {
            $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString $Script:RpcConfig

            $Submit = $Script:Fake.Calls | Where-Object Method -eq 'Submit'
            $Submit.Flags | Should -Be 0xff # CR_IN_ENCODEANY
            $Submit.Request | Should -Be $Script:Csr
            $Submit.Attributes | Should -BeNullOrEmpty
            $Submit.Config | Should -Be $Script:RpcConfig
            $Script:Fake.Calls.Method | Should -Not -Contain 'SetCredential'
        }

        It 'passes the template and further attributes newline-separated' {
            $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString $Script:RpcConfig -CertificateTemplate 'WebServer' -RequestAttributes 'SAN:dns=www.contoso.com'

            ($Script:Fake.Calls | Where-Object Method -eq 'Submit').Attributes |
                Should -Be ("SAN:dns=www.contoso.com" + [Environment]::NewLine + "CertificateTemplate:WebServer")
        }

        It 'submits with the machine identity for -MachineContext when elevated' {
            Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $true }

            $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString $Script:RpcConfig -MachineContext

            ($Script:Fake.Calls | Where-Object Method -eq 'Submit').Flags | Should -Be (0xff -bor 0x100000) # CR_IN_MACHINE
        }

        It 'refuses -MachineContext without elevation' {
            Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $false }

            { Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString $Script:RpcConfig -MachineContext -ErrorAction Stop } | Should -Throw '*Elevation*'
            Should -Invoke New-Object -ModuleName PSCertificateEnrollment -Times 0 -Exactly -ParameterFilter { $ComObject -eq 'CertificateAuthority.Request' }
        }
    }

    Context 'dispositions' {

        It 'reports disposition <Disposition> as "<Expected>"' -ForEach @(
            @{ Disposition = 0; Expected = 'Request is incomplete' }
            @{ Disposition = 1; Expected = 'There was an error during submission' }
            @{ Disposition = 2; Expected = 'Request was denied' }
            @{ Disposition = 4; Expected = 'Certificate was issued out of band' }
            @{ Disposition = 5; Expected = 'Request was taken under submission' }
            @{ Disposition = 6; Expected = 'Certificate has been revoked' }
        ) {
            $Script:Fake.Disposition = $Disposition
            $Script:Fake.LastStatus = -2146877437 # 0x80094003 CERTSRV_E_BAD_REQUESTSUBJECT

            $Result = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString $Script:RpcConfig

            $Result.Disposition | Should -Be $Disposition
            $Result.Result | Should -Be $Expected
            $Result.StatusCode | Should -Be '0x80094003'
            $Result.StatusCodeInt | Should -Be -2146877437
            $Result.Certificate | Should -BeNullOrEmpty
            $Result.RawCertificate | Should -BeNullOrEmpty
        }

        It 'writes an error for an unknown disposition' {
            $Script:Fake.Disposition = 99

            { Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString $Script:RpcConfig -ErrorAction Stop } | Should -Throw '*unsupported Disposition Code 99*'
        }
    }

    Context 'retrieval of a pending request' {

        It 'retrieves the request by its ID' {
            $Result = Get-IssuedCertificate -RequestId 42 -ConfigString $Script:RpcConfig

            $Result.Certificate.Thumbprint | Should -Be $Script:IssuedCertificate.Thumbprint
            $Retrieve = $Script:Fake.Calls | Where-Object Method -eq 'RetrievePending'
            $Retrieve.RequestId | Should -Be 42
            $Retrieve.Config | Should -Be $Script:RpcConfig
            $Script:Fake.Calls.Method | Should -Not -Contain 'Submit'
        }

        It 'rejects request ID 0' {
            { Get-IssuedCertificate -RequestId 0 -ConfigString $Script:RpcConfig } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Get-IssuedCertificate'
        }
    }

    Context 'submission over WSTEP' {

        It 'uses Kerberos for a *Kerberos endpoint' {
            $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString 'https://ces.contoso.com/Contoso-CA_CES_Kerberos/service.svc/CES'

            $Credential = $Script:Fake.Calls | Where-Object Method -eq 'SetCredential'
            $Credential.AuthType | Should -Be 2 # X509AuthKerberos
        }

        It 'uses the credential for a *UsernamePassword endpoint' {
            $Credential = [PSCredential]::new('CONTOSO\user', (ConvertTo-SecureString -String 'p@ss' -AsPlainText -Force))

            $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString 'https://ces.contoso.com/Contoso-CA_CES_UsernamePassword/service.svc/CES' -Credential $Credential

            $Call = $Script:Fake.Calls | Where-Object Method -eq 'SetCredential'
            $Call.AuthType | Should -Be 4 # X509AuthUsername
            $Call.Name | Should -Be 'CONTOSO\user'
            $Call.Secret | Should -Be 'p@ss'
        }

        It 'uses the client certificate for a *Certificate endpoint' {
            $Thumbprint = 'A' * 40

            $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString 'https://ces.contoso.com/Contoso-CA_CES_Certificate/service.svc/CES' -ClientCertificate $Thumbprint

            $Call = $Script:Fake.Calls | Where-Object Method -eq 'SetCredential'
            $Call.AuthType | Should -Be 8 # X509AuthCertificate
            $Call.Name | Should -Be $Thumbprint
        }

        It 'recognizes an endpoint URL starting with HTTPS:// in upper case' {
            $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString 'HTTPS://ces.contoso.com/Contoso-CA_CES_Kerberos/service.svc/CES'

            ($Script:Fake.Calls | Where-Object Method -eq 'SetCredential').AuthType | Should -Be 2
        }

        It 'requires <Missing> for a *<Endpoint> endpoint' -ForEach @(
            @{ Missing = '-Credential'; Endpoint = 'UsernamePassword'; Message = '*Credentials*' }
            @{ Missing = '-ClientCertificate'; Endpoint = 'Certificate'; Message = '*Client Authentication Certificate*' }
        ) {
            { Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString "https://ces.contoso.com/Contoso-CA_CES_$Endpoint/service.svc/CES" -ErrorAction Stop } |
                Should -Throw $Message
            $Script:Fake.Calls.Method | Should -Not -Contain 'Submit'
        }

        It 'releases the COM object when <Missing> is missing' -ForEach @(
            @{ Missing = '-Credential'; Endpoint = 'UsernamePassword' }
            @{ Missing = '-ClientCertificate'; Endpoint = 'Certificate' }
        ) {
            $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString "https://ces.contoso.com/Contoso-CA_CES_$Endpoint/service.svc/CES" -ErrorAction SilentlyContinue

            Should -Invoke Unregister-ComObject -ModuleName PSCertificateEnrollment -Times 1 -Exactly
        }
    }

    It 'releases the COM object after a submission' {
        $null = Get-IssuedCertificate -CertificateRequest $Script:Csr -ConfigString $Script:RpcConfig

        Should -Invoke Unregister-ComObject -ModuleName PSCertificateEnrollment -Times 1 -Exactly
    }
}
