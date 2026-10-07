# Tier 3: exercises the real CertEnroll SCEP objects against a fake SCEP server. GetCACert returns a
# throwaway CA and RA (ephemeral keys, never persisted), and the PKIOperation POST is captured, then
# decrypted with the RA key, so the inner PKCS#10 can be inspected. No network, no elevation.
#
# CertEnroll leaves a placeholder certificate and its key in CurrentUser\REQUEST because the fake
# server never issues anything - AfterAll removes those again.

BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
    Add-Type -AssemblyName System.Security

    $CaKey = [System.Security.Cryptography.RSA]::Create(2048)
    $CaRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=PesterIntegrationTest SCEP CA', $CaKey, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $CaRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $CaRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('KeyCertSign, DigitalSignature', $true))
    $Script:CaCert = $CaRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(1))

    # NDES returns an RA certificate next to the CA, and CertEnroll encrypts the PKCS#10 to it
    $RaKey = [System.Security.Cryptography.RSA]::Create(2048)
    $RaRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=PesterIntegrationTest SCEP RA', $RaKey, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $RaRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('DigitalSignature, KeyEncipherment', $true))
    $RaPublic = $RaRequest.Create($Script:CaCert, [DateTimeOffset]::UtcNow.AddHours(-1), [DateTimeOffset]::UtcNow.AddHours(23), [byte[]](1, 2, 3, 4))
    $Script:RaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($RaPublic, $RaKey)

    $Chain = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    [void]$Chain.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Script:RaCert.RawData))
    [void]$Chain.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Script:CaCert.RawData))
    $Script:GetCACert = $Chain.Export('Pkcs7')

    . "$PSScriptRoot\TestCertificateStore.ps1"
    $Script:StoreSnapshot = Get-StoreSnapshot

    Mock -ModuleName PSCertificateEnrollment Invoke-WebRequest -ParameterFilter { $Uri -like '*GetCACert*' } {
        [PSCustomObject]@{ Content = $Script:GetCACert }
    }
    Mock -ModuleName PSCertificateEnrollment Invoke-WebRequest -ParameterFilter { $Method -eq 'POST' } {
        $Script:RequestMessage = $Body
        [PSCustomObject]@{ Content = [byte[]](0x30, 0x00) }
    }

    # Runs Get-SCEPCertificate and returns the extensions of the PKCS#10 it sent, keyed by OID, as hex
    function Get-RequestedExtensions {
        param([hashtable]$Parameters)

        $Script:RequestMessage = $null
        $Parameters += @{
            ComputerName  = 'scep.invalid'
            Subject       = "CN=PesterIntegrationTest-$([Guid]::NewGuid())"
            CaCapabilites = 'POSTPKIOperation', 'SHA-256', 'AES'
            KeyLength     = 2048
        }

        # The fake server's response is not a valid PKI message, so the enrollment itself fails
        Get-SCEPCertificate @Parameters -ErrorAction SilentlyContinue

        $SignedMessage = [System.Security.Cryptography.Pkcs.SignedCms]::new()
        $SignedMessage.Decode($Script:RequestMessage)
        $EnvelopedMessage = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new()
        $EnvelopedMessage.Decode($SignedMessage.ContentInfo.Content)
        $EnvelopedMessage.Decrypt(
            $EnvelopedMessage.RecipientInfos[0],
            [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($Script:RaCert))

        $Pkcs10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
        $Pkcs10.InitializeDecode(
            [Convert]::ToBase64String([byte[]]$EnvelopedMessage.ContentInfo.Content),
            1 # XCN_CRYPT_STRING_BASE64
        )

        $Extensions = @{}
        foreach ($Extension in $Pkcs10.X509Extensions) {
            $Extensions[$Extension.ObjectId.Value] = [BitConverter]::ToString([Convert]::FromBase64String($Extension.RawData(1))) -replace '-'
        }
        $Extensions
    }
}

AfterAll {
    Remove-StoreDelta -Snapshot $Script:StoreSnapshot | Should -BeNullOrEmpty -Because 'tests must not add anything to CurrentUser\Root'

    $Script:CaCert.Dispose()
    $Script:RaCert.Dispose()

    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-SCEPCertificate' -Tag 'RequiresWindows' {

    Context 'without extension parameters' {

        It 'requests none of the optional extensions' {
            $Extensions = Get-RequestedExtensions -Parameters @{}

            # CertEnroll adds a Subject Key Identifier on its own, nothing else
            @($Extensions.Keys) | Should -Be @('2.5.29.14')
        }
    }

    Context 'with extension parameters' {

        BeforeAll {
            $Script:Extensions = Get-RequestedExtensions -Parameters @{
                CertificateTemplate = '1.3.6.1.4.1.311.21.8.1.2'
                KeyUsage            = 'NonRepudiation'
                Eku                 = 'ClientAuthentication', 'ServerAuthentication'
                AppPolicy           = 'ClientAuthentication'
                Smime               = 'aes256', 'sha256'
                Sid                 = 'S-1-5-21-1-2-3-500'
            }
        }

        It 'requests the <Name> extension exactly as its builder encodes it' -ForEach @(
            @{ Name = 'Certificate Template'; Oid = '1.3.6.1.4.1.311.21.7';  Builder = "New-TemplateExtension -ObjectIdentifier '1.3.6.1.4.1.311.21.8.1.2'" }
            @{ Name = 'Key Usage';            Oid = '2.5.29.15';             Builder = 'New-KeyUsageExtension -KeyUsage NonRepudiation' }
            @{ Name = 'Enhanced Key Usage';   Oid = '2.5.29.37';             Builder = 'New-ExtendedKeyUsageExtension -Eku ClientAuthentication, ServerAuthentication' }
            @{ Name = 'Application Policies'; Oid = '1.3.6.1.4.1.311.21.10'; Builder = 'New-ApplicationPoliciesExtension -ApplicationPolicies ClientAuthentication' }
            @{ Name = 'S/MIME Capabilities';  Oid = '1.2.840.113549.1.9.15'; Builder = 'New-SmimeCapabilitiesExtension -Smime aes256, sha256' }
            @{ Name = 'SID';                  Oid = '1.3.6.1.4.1.311.25.2';  Builder = "New-SidExtension -Sid 'S-1-5-21-1-2-3-500'" }
        ) {
            $Expected = InModuleScope PSCertificateEnrollment -Parameters @{ Builder = $Builder } {
                & ([ScriptBlock]::Create($Builder))
            }

            $Script:Extensions.Keys | Should -Contain $Oid
            $Script:Extensions[$Oid] | Should -Be ([BitConverter]::ToString([Convert]::FromBase64String($Expected)) -replace '-')
        }
    }

    Context 'renewal with a SigningCert' {

        It 'does not accept extension parameters, as a renewal inherits them' {
            $RenewalSet = (Get-Command Get-SCEPCertificate).ParameterSets | Where-Object { $_.Parameters.Name -contains 'SigningCert' }

            $RenewalSet.Parameters.Name | Should -Not -Contain 'CertificateTemplate'
            $RenewalSet.Parameters.Name | Should -Not -Contain 'KeyUsage'
            $RenewalSet.Parameters.Name | Should -Not -Contain 'Eku'
            $RenewalSet.Parameters.Name | Should -Not -Contain 'AppPolicy'
            $RenewalSet.Parameters.Name | Should -Not -Contain 'Smime'
            $RenewalSet.Parameters.Name | Should -Not -Contain 'Sid'
        }
    }
}
