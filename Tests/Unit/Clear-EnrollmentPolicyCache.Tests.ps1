BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Clear-EnrollmentPolicyCache' {

    Context 'user context' {

        # The real user profile is never touched: USERPROFILE points into TestDrive for each test
        BeforeEach {
            $Script:SavedUserProfile = $env:USERPROFILE
            $env:USERPROFILE = Join-Path $TestDrive ([Guid]::NewGuid())
            $Script:CachePath = Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\Windows\X509Enrollment'
        }

        AfterEach {
            $env:USERPROFILE = $Script:SavedUserProfile
        }

        It 'deletes the cached policy files of the user' {
            $null = New-Item -ItemType Directory -Path $Script:CachePath
            'a', 'b' | ForEach-Object { Set-Content -Path (Join-Path $Script:CachePath $_) -Value 'cached policy' }

            Clear-EnrollmentPolicyCache

            Get-ChildItem -Path $Script:CachePath -Force | Should -BeNullOrEmpty
        }

        It 'keeps the cache folder itself' {
            $null = New-Item -ItemType Directory -Path $Script:CachePath

            Clear-EnrollmentPolicyCache

            Test-Path -Path $Script:CachePath | Should -BeTrue
        }

        It 'does nothing when there is no cache yet' {
            { Clear-EnrollmentPolicyCache -ErrorAction Stop } | Should -Not -Throw
        }

        It 'is also available as Clear-XCEPEnrollmentPolicyCache' {
            (Get-Command Clear-XCEPEnrollmentPolicyCache).ResolvedCommand.Name | Should -Be 'Clear-EnrollmentPolicyCache'
        }
    }

    # Get-ChildItem and Remove-Item are mocked: nothing in ProgramData is ever listed or deleted
    Context 'machine context' {

        BeforeEach {
            Mock Test-Path -ModuleName PSCertificateEnrollment { $true }
            Mock Get-ChildItem -ModuleName PSCertificateEnrollment {}
            Mock Remove-Item -ModuleName PSCertificateEnrollment {}
        }

        It 'clears the machine cache when elevated' {
            Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $true }

            Clear-EnrollmentPolicyCache -MachineContext

            Should -Invoke Get-ChildItem -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
                $Path -eq "$env:ProgramData\Microsoft\Windows\X509Enrollment"
            }
        }

        It 'refuses -MachineContext without elevation' {
            Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $false }

            { Clear-EnrollmentPolicyCache -MachineContext -ErrorAction Stop } | Should -Throw '*Elevation*'
            Should -Invoke Get-ChildItem -ModuleName PSCertificateEnrollment -Times 0 -Exactly
        }
    }
}
