function New-EnrollmentPolicy {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({([System.Uri]($_)).IsAbsoluteUri})]
        [ValidateScript({([System.Uri]($_)).Scheme.Equals("https")})]
        [String]
        $Url,

        <#
        [ValidateSet(
            "None",
            "Anonymous",
            "Kerberos",
            "UserName",
            "ClientCertificate"
        )]
        [String]
        $Authentication = "Kerberos",
        #>

        [Parameter(Mandatory=$False)]
        [ValidateSet(
            "UseClientId",
            "AutoEnrollmentEnabled",
            "AllowUnTrustedCA"
        )]
        [String[]]
        $Settings = @("AutoEnrollmentEnabled"),

        [Alias("Machine")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext
    )

    process {

        if ($MachineContext.IsPresent) {

            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }

            $RegistryRoot = "HKLM:\Software\Microsoft\Cryptography\PolicyServers"
        }
        else {
            $RegistryRoot = "HKCU:\Software\Microsoft\Cryptography\PolicyServers"
        }

        <#
            X509AuthNone -- 0
            Anonymous -- 1
            Kerberos -- 2
            UserName -- 4
            ClientCertificate -- 8
        #>
        $Authflags = 0x2

        <#
            PsfLocationGroupPolicy -- 1
            PsfLocationRegistry -- 2
            PsfUseClientId -- 4
            PsfAutoEnrollmentEnabled -- 10 (16)
            PsfAllowUnTrustedCA -- 20 (32)
        #>
        $Flags = 0x2
        
        switch ($Settings) {
            "UseClientId" { $Flags = $Flags -bor 0x4 }
            "AutoEnrollmentEnabled" { $Flags = $Flags -bor 0x10 }
            "AllowUnTrustedCA" { $Flags = $Flags -bor 0x20 }
        }

        $EnrollmentServerUri = New-Object -TypeName System.Uri($Url)
        
        $Response = [xml](Get-XCEPEnrollmentPolicy -ComputerName $EnrollmentServerUri.Host -Port $EnrollmentServerUri.Port -Suffix $EnrollmentServerUri.PathAndQuery.Replace("service.svc/CEP","").Trim("/") -ErrorAction Stop)

        $PolicyId = $Response.Envelope.Body.GetPoliciesResponse.response.policyID
        $FriendlyName = $Response.Envelope.Body.GetPoliciesResponse.response.policyFriendlyName

        # URL -> ToLower -> Unicode Bytes -> SHA1 Hash -> ToLower
        $Identifier = (Get-Hash -Bytes ([System.Text.Encoding]::Unicode.GetBytes($Url.ToLower())) -HashAlgorithm "SHA1").ToLower()

        New-Item -Path $RegistryRoot -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path "$RegistryRoot\$Identifier" -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "$RegistryRoot\$Identifier" -Name "URL" -Type String -Value $Url -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "$RegistryRoot\$Identifier" -Name "PolicyID" -Type String -Value $PolicyId -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "$RegistryRoot\$Identifier" -Name "FriendlyName" -Type String -Value $FriendlyName -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "$RegistryRoot\$Identifier" -Name "Flags" -Type DWord -Value $Flags -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "$RegistryRoot\$Identifier" -Name "AuthFlags" -Type DWord -Value $Authflags -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "$RegistryRoot\$Identifier" -Name "Cost" -Type DWord -Value 0x7ffffffd -Force -ErrorAction SilentlyContinue | Out-Null

        Get-EnrollmentPolicy -Identifier $Identifier -MachineContext:$MachineContext.IsPresent
    }
}