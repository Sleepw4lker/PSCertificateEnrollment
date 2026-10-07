BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'New-AkiExtension' {

    It 'encodes the key identifier as the [0] keyIdentifier of an AuthorityKeyIdentifier' {
        InModuleScope PSCertificateEnrollment {
            $Result = [BitConverter]::ToString([Convert]::FromBase64String((New-AkiExtension -Aki '0102030405060708090A0B0C0D0E0F1011121314'))) -replace '-'

            # 30 16                              SEQUENCE (AuthorityKeyIdentifier)
            #   80 14 0102...1314                [0] keyIdentifier (20 bytes)
            $Result | Should -Be '301680140102030405060708090A0B0C0D0E0F1011121314'
        }
    }
}
