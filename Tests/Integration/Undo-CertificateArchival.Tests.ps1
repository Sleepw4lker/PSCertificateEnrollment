# Archives real certificates in CurrentUser\My and restores them. Every certificate and key the
# tests create is removed again in AfterAll - archived or not.

BeforeDiscovery {
    $IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    . "$PSScriptRoot\TestCertificateStore.ps1"
    $Script:StoreSnapshot = Get-StoreSnapshot

    # A certificate in CurrentUser\My that is archived, so listing the store no longer shows it
    function New-ArchivedCertificate {
        $Certificate = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddHours(1) `
            -Subject "CN=PesterIntegrationTest-$([Guid]::NewGuid())"
        Set-Archived -Thumbprint $Certificate.Thumbprint -Archived $true
        $Certificate.Thumbprint
    }

    function Set-Archived {
        param([string] $Thumbprint, [bool] $Archived)
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
        $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite, IncludeArchived')
        try {
            ($Store.Certificates | Where-Object Thumbprint -eq $Thumbprint).Archived = $Archived
        }
        finally {
            $Store.Close()
        }
    }

    function Test-Listed {
        param([string] $Thumbprint)
        [bool](Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object Thumbprint -eq $Thumbprint)
    }
}

AfterAll {
    Remove-StoreDelta -Snapshot $Script:StoreSnapshot | Should -BeNullOrEmpty -Because 'tests must not add anything to CurrentUser\Root'
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Undo-CertificateArchival' -Tag 'RequiresWindows' {

    It 'restores an archived certificate, given the store as a Cert: path' {
        $Thumbprint = New-ArchivedCertificate
        Test-Listed -Thumbprint $Thumbprint | Should -BeFalse

        Undo-CertificateArchival -Thumbprint $Thumbprint -CertStoreLocation 'Cert:\CurrentUser\My'

        Test-Listed -Thumbprint $Thumbprint | Should -BeTrue
    }

    It 'restores an archived certificate, given the store as an X509Store' {
        $Thumbprint = New-ArchivedCertificate
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')

        Undo-CertificateArchival -Thumbprint $Thumbprint -CertStoreLocation $Store -ErrorAction Stop

        Test-Listed -Thumbprint $Thumbprint | Should -BeTrue
    }

    It 'leaves the store alone for a thumbprint it does not contain' {
        $Before = @(Get-ChildItem -Path Cert:\CurrentUser\My).Count

        { Undo-CertificateArchival -Thumbprint ('0' * 40) -CertStoreLocation 'Cert:\CurrentUser\My' -ErrorAction Stop } | Should -Not -Throw

        @(Get-ChildItem -Path Cert:\CurrentUser\My).Count | Should -Be $Before
    }

    It 'refuses a LocalMachine store without elevation' -Skip:$IsElevated {
        { Undo-CertificateArchival -Thumbprint ('0' * 40) -CertStoreLocation 'Cert:\LocalMachine\My' -ErrorAction Stop } | Should -Throw '*Elevation*'
    }

    It 'rejects a thumbprint that is not 40 hex characters' {
        { Undo-CertificateArchival -Thumbprint 'ABC' -CertStoreLocation 'Cert:\CurrentUser\My' } |
            Should -Throw -ErrorId 'ParameterArgumentValidationError,Undo-CertificateArchival'
    }
}
