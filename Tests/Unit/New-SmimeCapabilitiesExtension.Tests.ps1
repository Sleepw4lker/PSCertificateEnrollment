BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-SmimeCapabilitiesExtension' {

    It 'encodes aes256 without parameters' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-SmimeCapabilitiesExtension -Smime aes256))) -replace '-'

            # 30 0D                              SEQUENCE (SMIMECapabilities)
            #   30 0B                            SEQUENCE (SMIMECapability)
            #     06 09 60864801650304012A       OID 2.16.840.1.101.3.4.1.42 (aes256-CBC)
            $Result | Should -Be '300D300B060960864801650304012A'
        }
    }

    It 'encodes rc2 with a 128 bit key length parameter' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-SmimeCapabilitiesExtension -Smime rc2))) -replace '-'

            # 30 10
            #   30 0E
            #     06 08 2A864886F70D0302         OID 1.2.840.113549.3.2 (rc2-CBC)
            #     02 02 0080                     INTEGER 128
            $Result | Should -Be '3010300E06082A864886F70D030202020080'
        }
    }

    It 'keeps input order, since capabilities are listed by preference' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-SmimeCapabilitiesExtension -Smime sha256, aes256))) -replace '-'

            # 30 1A <sha256> <aes256>
            $Result | Should -Be ('301A' +
                '300B0609608648016503040201' +
                '300B060960864801650304012A')
        }
    }

    It 'removes duplicates, keeping the first occurrence' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-SmimeCapabilitiesExtension -Smime sha256, aes256, sha256, aes256))) -replace '-'

            $Result | Should -Be ('301A' +
                '300B0609608648016503040201' +
                '300B060960864801650304012A')
        }
    }

    It 'treats differently cased names as duplicates' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-SmimeCapabilitiesExtension -Smime aes256, AES256))) -replace '-'

            $Result | Should -Be '300D300B060960864801650304012A'
        }
    }

    It 'still encodes rc2 with 128 bits when given in upper case' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-SmimeCapabilitiesExtension -Smime RC2))) -replace '-'

            $Result | Should -Be '3010300E06082A864886F70D030202020080'
        }
    }

    It 'accepts the SmimeCapabilities alias' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-SmimeCapabilitiesExtension -SmimeCapabilities aes256))) -replace '-'

            $Result | Should -Be '300D300B060960864801650304012A'
        }
    }

    It 'rejects a value outside the ValidateSet' {
        InModuleScope PSCertificateEnrollment {
            { New-SmimeCapabilitiesExtension -Smime 'Bogus' } | Should -Throw
        }
    }
}
