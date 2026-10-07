BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-ExtendedKeyUsageExtension' {

    It 'encodes ServerAuthentication as a SEQUENCE of one OID' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-ExtendedKeyUsageExtension -Eku ServerAuthentication))) -replace '-'

            # 30 0A                              SEQUENCE (ExtKeyUsageSyntax)
            #   06 08 2B06010505070301           OID 1.3.6.1.5.5.7.3.1 (serverAuth)
            $Result | Should -Be '300A06082B06010505070301'
        }
    }

    It 'sorts by name and removes duplicates' {
        InModuleScope PSCertificateEnrollment {
            $Bytes = [Convert]::FromBase64String((New-ExtendedKeyUsageExtension -Eku ServerAuthentication, ClientAuthentication, ClientAuthentication))

            # 30 14
            #   06 08 2B06010505070302           OID 1.3.6.1.5.5.7.3.2 (clientAuth)
            #   06 08 2B06010505070301           OID 1.3.6.1.5.5.7.3.1 (serverAuth)
            [BitConverter]::ToString($Bytes) -replace '-' | Should -Be '301406082B0601050507030206082B06010505070301'

            $Decoded = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
                [System.Security.Cryptography.AsnEncodedData]::new('2.5.29.37', $Bytes), $false)
            @($Decoded.EnhancedKeyUsages | ForEach-Object { $_.Value }) | Should -Be @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1')
        }
    }

    It 'treats differently cased names as duplicates' {
        InModuleScope PSCertificateEnrollment {
            # Used to fail inside CertEnroll ("The file exists. 0x80070050") and return nothing
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((
                New-ExtendedKeyUsageExtension -Eku ServerAuthentication, serverauthentication -ErrorAction Stop
            ))) -replace '-'

            $Result | Should -Be '300A06082B06010505070301'
        }
    }

    It 'accepts the <Alias> alias' -ForEach @(
        @{ Alias = 'ExtendedKeyUsage' }
        @{ Alias = 'EnhancedKeyUsage' }
    ) {
        InModuleScope PSCertificateEnrollment -Parameters @{ Alias = $Alias } {
            $Parameters = @{ $Alias = 'ServerAuthentication' }
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-ExtendedKeyUsageExtension @Parameters))) -replace '-'

            $Result | Should -Be '300A06082B06010505070301'
        }
    }

    It 'rejects a value outside the ValidateSet' {
        InModuleScope PSCertificateEnrollment {
            { New-ExtendedKeyUsageExtension -Eku 'Bogus' } | Should -Throw
        }
    }
}
