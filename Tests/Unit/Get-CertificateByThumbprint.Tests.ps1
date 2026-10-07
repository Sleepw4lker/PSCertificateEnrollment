BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
    $Script:ValidThumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-CertificateByThumbprint' {

    Context 'certificate found in CurrentUser store' {

        It 'returns the certificate without checking LocalMachine' {
            InModuleScope PSCertificateEnrollment -Parameters @{ Thumbprint = $Script:ValidThumbprint } {

                Mock Get-ChildItem { $null }
                Mock Get-ChildItem -ParameterFilter { $Path -like 'Cert:\CurrentUser\*' } {
                    [PSCustomObject]@{ Thumbprint = $Thumbprint; Subject = 'CN=PesterTest' }
                }

                $Result = Get-CertificateByThumbprint -Thumbprint $Thumbprint

                $Result.Thumbprint | Should -Be $Thumbprint
                Should -Invoke Get-ChildItem -ParameterFilter { $Path -like 'Cert:\LocalMachine\*' } -Times 0
            }
        }
    }

    Context 'certificate found only in LocalMachine store' {

        It 'falls back to LocalMachine and returns the certificate' {
            InModuleScope PSCertificateEnrollment -Parameters @{ Thumbprint = $Script:ValidThumbprint } {

                Mock Get-ChildItem { $null }
                Mock Get-ChildItem -ParameterFilter { $Path -like 'Cert:\LocalMachine\*' } {
                    [PSCustomObject]@{ Thumbprint = $Thumbprint; Subject = 'CN=PesterTest' }
                }

                $Result = Get-CertificateByThumbprint -Thumbprint $Thumbprint
                $Result.Thumbprint | Should -Be $Thumbprint
            }
        }
    }

    Context 'certificate not found in either store' {

        It 'throws' {
            InModuleScope PSCertificateEnrollment -Parameters @{ Thumbprint = $Script:ValidThumbprint } {

                Mock Get-ChildItem { $null }

                { Get-CertificateByThumbprint -Thumbprint $Thumbprint } | Should -Throw '*not found*'
            }
        }
    }
}
