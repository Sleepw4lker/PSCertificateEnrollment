BeforeAll {
    Import-Module "$PSScriptRoot\..\..\PSCertificateEnrollment.psd1" -Force

    # A client-side stand-in for the RDP listener's settings - CIM is never queried or changed
    function New-TSGeneralSetting {
        param([string] $Thumbprint)
        New-CimInstance -ClassName Win32_TSGeneralSetting -Namespace root/cimv2/terminalservices -ClientOnly -Property @{
            TerminalName           = 'RDP-tcp'
            SSLCertificateSHA1Hash = $Thumbprint
        }
    }

    # In-memory certificate with the given EKUs, made to look like it came from the given store.
    # The note property is kept with the certificate object itself; nothing touches a real store.
    function New-TestCertificate {
        param([string[]] $Eku, [string] $Store = 'LocalMachine\My')
        $Key = [System.Security.Cryptography.RSA]::Create(2048)
        $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=PesterTest RDP', $Key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if ($Eku) {
            $Oids = [System.Security.Cryptography.OidCollection]::new()
            $Eku | ForEach-Object { [void]$Oids.Add([System.Security.Cryptography.Oid]::new($_)) }
            $Request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($Oids, $false))
        }
        $Certificate = $Request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
        $Certificate | Add-Member -NotePropertyName PSParentPath -NotePropertyValue "Microsoft.PowerShell.Security\Certificate::$Store"
        $Certificate
    }

    $Script:ServerAuth = '1.3.6.1.5.5.7.3.1'
    $Script:RemoteDesktopAuth = '1.3.6.1.4.1.311.54.1.2'
    $Script:Thumbprint = 'A' * 40
}

AfterAll {
    Remove-Module -Name PSCertificateEnrollment -Force -ErrorAction SilentlyContinue
}

Describe 'Get-RemoteDesktopCertificate' {

    BeforeEach {
        Mock Get-ChildItem -ModuleName PSCertificateEnrollment {}
    }

    It 'returns nothing when no certificate is configured' {
        Mock Get-CimInstance -ModuleName PSCertificateEnrollment { New-TSGeneralSetting -Thumbprint ('0' * 40) }

        Get-RemoteDesktopCertificate | Should -BeNullOrEmpty
        Should -Invoke Get-ChildItem -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }

    It 'looks for the configured certificate in the <Store> store' -ForEach @(
        @{ Store = 'My' }
        @{ Store = 'Remote Desktop' }
    ) {
        Mock Get-CimInstance -ModuleName PSCertificateEnrollment { New-TSGeneralSetting -Thumbprint $Script:Thumbprint }
        Mock Get-ChildItem -ModuleName PSCertificateEnrollment -ParameterFilter { $Path -eq "Cert:\LocalMachine\$Store\$Script:Thumbprint" } { "certificate from $Store" }

        Get-RemoteDesktopCertificate | Should -Be "certificate from $Store"
    }

    It 'reads the setting of the RDP-tcp listener' {
        Mock Get-CimInstance -ModuleName PSCertificateEnrollment { New-TSGeneralSetting -Thumbprint ('0' * 40) }

        $null = Get-RemoteDesktopCertificate

        Should -Invoke Get-CimInstance -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $ClassName -eq 'Win32_TSGeneralSetting' -and $Namespace -eq 'root\cimv2\terminalservices' -and $Filter -eq "TerminalName='RDP-tcp'"
        }
    }

    # E.g. access denied when not elevated: listing the whole store instead would return every machine certificate
    It 'returns nothing when the setting cannot be read' {
        Mock Get-CimInstance -ModuleName PSCertificateEnrollment {}
        Mock Get-ChildItem -ModuleName PSCertificateEnrollment { 'some machine certificate' }

        Get-RemoteDesktopCertificate | Should -BeNullOrEmpty
        Should -Invoke Get-ChildItem -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }
}

# Get-CimInstance and Set-CimInstance are mocked: the RDP configuration is never changed
Describe 'Set-RemoteDesktopCertificate' {

    BeforeAll {
        $Script:Certificate = New-TestCertificate -Eku $Script:ServerAuth
    }

    AfterAll {
        $Script:Certificate.Dispose()
    }

    BeforeEach {
        Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $true }
        Mock Get-CimInstance -ModuleName PSCertificateEnrollment { New-TSGeneralSetting -Thumbprint ('0' * 40) }
        Mock Set-CimInstance -ModuleName PSCertificateEnrollment {}
    }

    It 'sets the certificate of the RDP-tcp listener and returns $true' {
        Set-RemoteDesktopCertificate -Certificate $Script:Certificate | Should -BeTrue

        Should -Invoke Set-CimInstance -ModuleName PSCertificateEnrollment -Times 1 -Exactly -ParameterFilter {
            $CimInstance.TerminalName -eq 'RDP-tcp' -and $Property['SSLCertificateSHA1Hash'] -eq $Script:Certificate.Thumbprint
        }
    }

    It 'accepts a certificate for <Case>' -ForEach @(
        @{ Case = 'Remote Desktop Authentication'; Eku = '1.3.6.1.4.1.311.54.1.2' }
    ) {
        $Certificate = New-TestCertificate -Eku $Eku
        try {
            Set-RemoteDesktopCertificate -Certificate $Certificate | Should -BeTrue
        }
        finally {
            $Certificate.Dispose()
        }
    }

    It 'refuses to run without elevation' {
        Mock Test-IsElevated -ModuleName PSCertificateEnrollment { $false }

        { Set-RemoteDesktopCertificate -Certificate $Script:Certificate -ErrorAction Stop } | Should -Throw '*Elevation*'
        Should -Invoke Set-CimInstance -ModuleName PSCertificateEnrollment -Times 0 -Exactly
    }

    It 'does not report success when the setting cannot be written' {
        # Like the real cmdlet: a non-terminating error, unless the caller asks for -ErrorAction Stop
        Mock Set-CimInstance -ModuleName PSCertificateEnrollment {
            $Action = if ($PesterBoundParameters.ContainsKey('ErrorAction')) { $PesterBoundParameters['ErrorAction'] } else { 'Continue' }
            Write-Error 'Access denied' -ErrorAction $Action
        }

        Set-RemoteDesktopCertificate -Certificate $Script:Certificate -ErrorAction SilentlyContinue 2>$null | Should -BeNullOrEmpty
    }

    It 'rejects a certificate <Case>' -ForEach @(
        @{ Case = 'without a suitable EKU'; Eku = @('1.3.6.1.5.5.7.3.2'); Store = 'LocalMachine\My'; PublicOnly = $false }
        @{ Case = 'from the user store'; Eku = @('1.3.6.1.5.5.7.3.1'); Store = 'CurrentUser\My'; PublicOnly = $false }
        @{ Case = 'without a private key'; Eku = @('1.3.6.1.5.5.7.3.1'); Store = 'LocalMachine\My'; PublicOnly = $true }
    ) {
        $Certificate = New-TestCertificate -Eku $Eku -Store $Store
        if ($PublicOnly) {
            $WithKey = $Certificate
            $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($WithKey.RawData)
            $Certificate | Add-Member -NotePropertyName PSParentPath -NotePropertyValue "Microsoft.PowerShell.Security\Certificate::$Store"
            $WithKey.Dispose()
        }
        try {
            { Set-RemoteDesktopCertificate -Certificate $Certificate } | Should -Throw -ErrorId 'ParameterArgumentValidationError,Set-RemoteDesktopCertificate'
        }
        finally {
            $Certificate.Dispose()
        }
    }
}
