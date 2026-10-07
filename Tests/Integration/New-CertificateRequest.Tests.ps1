# Tier 3: exercises the real CertEnroll COM objects and the real CurrentUser\My certificate
# store. Requires a Windows box with the CertEnroll COM components registered (any normal
# Windows install qualifies - no elevation needed for CurrentUser-context operations).
#
# Backlog note: Helpers/Test.ps1 (removed) listed further manual scenarios - ECC keys, legacy
# CSP vs. Software/TPM KSP, Enrollment Agent-signed requests, machine-context (elevated) key
# creation - that belong in this tier/Tier 4 as this suite grows.

BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    # Creating a CSR leaves a placeholder certificate and its key in CurrentUser\REQUEST, and a
    # self-signed certificate lands in My with a copy in CA - AfterAll removes all of it again
    . "$PSScriptRoot\TestCertificateStore.ps1"
    $Script:StoreSnapshot = Get-StoreSnapshot

    # Returns the extensions of a CSR, keyed by OID, as hex
    function Get-RequestExtensions {
        param([String]$Request)

        $Pkcs10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
        $Pkcs10.InitializeDecode($Request, 3) # XCN_CRYPT_STRING_BASE64REQUESTHEADER

        $Extensions = @{}
        foreach ($Extension in $Pkcs10.X509Extensions) {
            $Extensions[$Extension.ObjectId.Value] = [BitConverter]::ToString([Convert]::FromBase64String($Extension.RawData(1))) -replace '-'
        }
        $Extensions
    }
}

AfterAll {
    Remove-StoreDelta -Snapshot $Script:StoreSnapshot | Should -BeNullOrEmpty -Because 'tests must not add anything to CurrentUser\Root'

    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-CertificateRequest' -Tag 'RequiresWindows' {

    Context '-SelfSign' {

        It 'creates and installs a self-signed certificate with the requested Subject' {
            $SubjectName = "CN=PesterIntegrationTest-$([Guid]::NewGuid())"

            $Script:Certificate = New-CertificateRequest -Subject $SubjectName -SelfSign

            $Script:Certificate | Should -Not -BeNullOrEmpty
            $Script:Certificate.Subject | Should -Be $SubjectName
            $Script:Certificate.HasPrivateKey | Should -BeTrue
            Test-Path "Cert:\CurrentUser\My\$($Script:Certificate.Thumbprint)" | Should -BeTrue
        }
    }

    Context 'without -SelfSign' {

        It 'returns a PKCS#10 request instead of installing a certificate' {
            $SubjectName = "CN=PesterIntegrationTest-$([Guid]::NewGuid())"

            $Result = New-CertificateRequest -Subject $SubjectName

            $Result | Should -BeOfType [String]
            $Result | Should -Match '-----BEGIN NEW CERTIFICATE REQUEST-----'
        }

        It 'includes the Certificate Template and Application Policies extensions' {
            $SubjectName = "CN=PesterIntegrationTest-$([Guid]::NewGuid())"

            $Extensions = Get-RequestExtensions -Request (
                New-CertificateRequest -Subject $SubjectName -CertificateTemplate '1.3.6.1.4.1.311.21.8.1.2' -AppPolicy ClientAuthentication
            )

            # SEQUENCE { OID 1.3.6.1.4.1.311.21.8.1.2, INTEGER 100, INTEGER 1 }
            $Extensions['1.3.6.1.4.1.311.21.7'] | Should -Be '3013060B2B06010401823715080102020164020101'

            # SEQUENCE { SEQUENCE { OID 1.3.6.1.5.5.7.3.2 } }
            $Extensions['1.3.6.1.4.1.311.21.10'] | Should -Be '300C300A06082B06010505070302'
        }
    }
}
