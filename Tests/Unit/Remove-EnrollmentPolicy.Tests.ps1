BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    $Script:Identifier = 'a' * 40
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

# Remove-Item is mocked: the registry is never touched
Describe 'Remove-EnrollmentPolicy' {

    BeforeEach {
        Mock Remove-Item -ModuleName PSCertificateEnrollment {}
    }

    It 'removes the policy server of the user' {
        Remove-EnrollmentPolicy -Identifier $Script:Identifier

        Should -Invoke Remove-Item -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Path -eq "HKCU:\Software\Microsoft\Cryptography\PolicyServers\$Script:Identifier"
        }
    }

    It 'removes the policy server of the machine when elevated' {
        Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $true }

        Remove-EnrollmentPolicy -Identifier $Script:Identifier -MachineContext

        Should -Invoke Remove-Item -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $Path -eq "HKLM:\Software\Microsoft\Cryptography\PolicyServers\$Script:Identifier"
        }
    }

    It 'refuses -MachineContext without elevation' {
        Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $false }

        { Remove-EnrollmentPolicy -Identifier $Script:Identifier -MachineContext -ErrorAction Stop } | Should -Throw '*Elevation*'
        Should -Invoke Remove-Item -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }

    It 'removes every identifier piped in' {
        ('a' * 40), ('b' * 40) | Remove-EnrollmentPolicy

        Should -Invoke Remove-Item -ModuleName PSCertificateEnrollment -Times 2 -Exactly
    }

    It 'rejects an identifier that is not a SHA-1 hash' {
        { Remove-EnrollmentPolicy -Identifier 'not-a-hash' } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Remove-EnrollmentPolicy'
        Should -Invoke Remove-Item -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }
}
