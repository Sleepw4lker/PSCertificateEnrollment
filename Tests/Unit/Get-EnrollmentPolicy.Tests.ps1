BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    $Script:UserRoot = 'HKCU:\Software\Microsoft\Cryptography\PolicyServers'
    $Script:MachineRoot = 'HKLM:\Software\Microsoft\Cryptography\PolicyServers'
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

# Get-Item and Get-ChildItem are mocked: the registry is never read
Describe 'Get-EnrollmentPolicy' {

    BeforeEach {
        Mock Get-Item -ModuleName PSCertificateEnrollment { [PSCustomObject]@{ Path = $Path } }
        Mock Get-ChildItem -ModuleName PSCertificateEnrollment { [PSCustomObject]@{ Path = $Path } }
    }

    It 'lists all policy servers of the user' {
        (Get-EnrollmentPolicy).Path | Should -Be $Script:UserRoot
        Should -Invoke Get-Item -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }

    It 'lists all policy servers of the machine for -MachineContext' {
        (Get-EnrollmentPolicy -MachineContext).Path | Should -Be $Script:MachineRoot
    }

    It 'returns a single policy server for -Identifier' {
        $Identifier = 'a' * 40

        (Get-EnrollmentPolicy -Identifier $Identifier).Path | Should -Be "$Script:UserRoot\$Identifier"
        Should -Invoke Get-ChildItem -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }

    It 'returns a policy server for every identifier piped in' {
        $Result = ('a' * 40), ('b' * 40) | Get-EnrollmentPolicy -MachineContext

        $Result.Path | Should -Be @("$Script:MachineRoot\$('a' * 40)", "$Script:MachineRoot\$('b' * 40)")
    }

    It 'rejects an identifier that is not a SHA-1 hash' {
        { Get-EnrollmentPolicy -Identifier 'not-a-hash' } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Get-EnrollmentPolicy'
    }
}
