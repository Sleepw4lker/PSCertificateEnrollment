BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Test-IsElevated' {

    It 'tells whether the current process runs as Administrator' {
        $Expected = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

        InModuleScope PSCertificateEnrollment -Parameters @{ Expected = $Expected } {
            param($Expected)
            $Result = Test-IsElevated
            $Result | Should -BeOfType [Bool]
            $Result | Should -Be $Expected
        }
    }
}
