BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    $Script:Url = 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP'

    # How Windows names the registry key of a policy server: SHA-1 of the lower-case URL as UTF-16
    function Get-ExpectedIdentifier {
        param([string] $Url)
        $Sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            ([BitConverter]::ToString($Sha1.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Url.ToLower()))) -replace '-').ToLower()
        }
        finally {
            $Sha1.Dispose()
        }
    }

    $Script:PolicyResponse = @'
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <response>
        <policyID>{11111111-2222-3333-4444-555555555555}</policyID>
        <policyFriendlyName>Contoso Policy</policyFriendlyName>
      </response>
    </GetPoliciesResponse>
  </s:Body>
</s:Envelope>
'@
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

# Every registry cmdlet is mocked: nothing is written, not even to HKCU
Describe 'New-EnrollmentPolicy' {

    BeforeEach {
        Mock Get-XCEPEnrollmentPolicy -ModuleName PSCertificateEnrollment { $Script:PolicyResponse }
        Mock New-Item -ModuleName PSCertificateEnrollment {}
        Mock Set-ItemProperty -ModuleName PSCertificateEnrollment {}
        Mock Get-EnrollmentPolicy -ModuleName PSCertificateEnrollment { 'policy server key' }
    }

    It 'registers the policy server under its identifier and returns it' {
        $Identifier = Get-ExpectedIdentifier -Url $Script:Url
        $Key = "HKCU:\Software\Microsoft\Cryptography\PolicyServers\$Identifier"

        New-EnrollmentPolicy -Url $Script:Url | Should -Be 'policy server key'

        Should -Invoke New-Item -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter { $Path -eq $Key }
        Should -Invoke Get-EnrollmentPolicy -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Identifier -eq (Get-ExpectedIdentifier -Url $Script:Url) -and -not $MachineContext
        }
    }

    It 'writes <Property> = <Expected>' -ForEach @(
        @{ Property = 'URL'; Expected = 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP' }
        @{ Property = 'PolicyID'; Expected = '{11111111-2222-3333-4444-555555555555}' }
        @{ Property = 'FriendlyName'; Expected = 'Contoso Policy' }
        @{ Property = 'AuthFlags'; Expected = 2 }
        @{ Property = 'Cost'; Expected = 0x7ffffffd }
    ) {
        $null = New-EnrollmentPolicy -Url $Script:Url

        Should -Invoke Set-ItemProperty -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Name -eq $Property -and $Value -eq $Expected
        }
    }

    It 'sets Flags to <ExpectedFlags> for -Settings <Settings>' -ForEach @(
        # PsfLocationRegistry (0x2) is always set
        @{ Settings = @('AutoEnrollmentEnabled'); ExpectedFlags = 0x12 }
        @{ Settings = @('UseClientId'); ExpectedFlags = 0x6 }
        @{ Settings = @('AllowUnTrustedCA'); ExpectedFlags = 0x22 }
        @{ Settings = @('UseClientId', 'AutoEnrollmentEnabled', 'AllowUnTrustedCA'); ExpectedFlags = 0x36 }
    ) {
        $null = New-EnrollmentPolicy -Url $Script:Url -Settings $Settings

        Should -Invoke Set-ItemProperty -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'Flags' -and $Value -eq $ExpectedFlags
        }
    }

    It 'asks the endpoint for its policy, derived from <Case>' -ForEach @(
        @{ Case = 'the default port'; Url = 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP'; ExpectedPort = 443 }
        @{ Case = 'an explicit port'; Url = 'https://cep.contoso.com:8443/ADPolicyProvider_CEP_Kerberos/service.svc/CEP'; ExpectedPort = 8443 }
    ) {
        $null = New-EnrollmentPolicy -Url $Url

        Should -Invoke Get-XCEPEnrollmentPolicy -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $ComputerName -eq 'cep.contoso.com' -and $Port -eq $ExpectedPort -and $Suffix -eq 'ADPolicyProvider_CEP_Kerberos'
        }
    }

    It 'derives the suffix from a URL whose service path is written in another case' {
        $null = New-EnrollmentPolicy -Url 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/Service.svc/cep'

        Should -Invoke Get-XCEPEnrollmentPolicy -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Suffix -eq 'ADPolicyProvider_CEP_Kerberos'
        }
    }

    It 'writes nothing when the policy cannot be retrieved' {
        Mock Get-XCEPEnrollmentPolicy -ModuleName PSCertificateEnrollment { throw 'Unable to connect to the remote server' }

        { New-EnrollmentPolicy -Url $Script:Url } | Should -Throw '*Unable to connect*'
        Should -Invoke New-Item -ModuleName PSCertificateEnrollment -Times 0 -Exactly
        Should -Invoke Set-ItemProperty -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }

    It 'registers the policy server for the machine when elevated' {
        Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $true }

        $null = New-EnrollmentPolicy -Url $Script:Url -MachineContext

        Should -Invoke New-Item -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Path -eq "HKLM:\Software\Microsoft\Cryptography\PolicyServers\$(Get-ExpectedIdentifier -Url $Script:Url)"
        }
        Should -Invoke Set-ItemProperty -ModuleName PSCertificateEnrollment -Times 0 -Exactly -ParameterFilter { $Path -like 'HKCU:*' }
    }

    It 'refuses -MachineContext without elevation' {
        Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $false }

        { New-EnrollmentPolicy -Url $Script:Url -MachineContext -ErrorAction Stop } | Should -Throw '*Elevation*'
        Should -Invoke Get-XCEPEnrollmentPolicy -ModuleName PSCertificateEnrollment -Times 0 -Exactly
        Should -Invoke New-Item -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }

    It 'rejects <Case>' -ForEach @(
        @{ Case = 'a plain http URL'; Url = 'http://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP' }
        @{ Case = 'a relative URL'; Url = 'ADPolicyProvider_CEP_Kerberos/service.svc/CEP' }
    ) {
        { New-EnrollmentPolicy -Url $Url } | Should -Throw -ErrorId 'ParameterArgumentValidationError,New-EnrollmentPolicy'
        Should -Invoke New-Item -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }
}
