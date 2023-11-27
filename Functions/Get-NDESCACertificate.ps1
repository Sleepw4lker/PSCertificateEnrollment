<#
    .SYNOPSIS
    Requests a Certificate from an NDES Server via the SCEP Protocol.
    This works on Windows 8.1 and newer Operating Systems.

    .PARAMETER ComputerName
    Specifies the Host Name or IP Address of the NDES Server.
    If using SSL, this must match the NDES Server's identity as specified in its SSL Server Certificate.

    .PARAMETER UseSSL
    Forces the connection to use SSL Encryption. Not necessary from a security perspective,
    as the SCEP Message's confidential partsd are encrypted with the NDES RA Certificates anyway.

    .PARAMETER Port
    Specifies the Network Port of the NDES Server to be used.
    Only necessary if your NDES Server is running on a non-default Port for some reason.
    Defaults to Port 80 without SSL and 443 with SSL.

    .PARAMETER CertificateFolder
    Path of folder where CA certifcates are written. Defaults to current directory. 
    Filenames will be CA-cert-<i>.crt, where i is a number from 0 to n.
    Only used when exporting to files.

    .PARAMETER Export
    Export CA certificates to files. 
    Import, Export or both must be specified.

    .PARAMETER Import
    Import the CA certificates into the computer Trusted Root Certification Authorities.
    Import, Export or both must be specified.

    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate. Returns the CA Certificate returned by the NDES Server.
#>
Function Get-NDESCACertificate {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [String]
        $ComputerName,

        [Alias("SSL")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $UseSSL = $False,

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,65535)]
        [Int]
        $Port,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Suffix = "certsrv/mscep/mscep.dll",

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateFolder = $(Get-Location),

        [Parameter(Mandatory=$False)]
        [Switch]
        $Import = $False,

        [Parameter(Mandatory=$False)]
        [Switch]
        $Export = $False

    )

    begin  {

        If (-not ($Import.IsPresent -or $Export.IsPresent)) {
          throw 'Missing switch. Import, Export or both must be specified.'
        }
    
        Add-Type -AssemblyName System.Security

        # This hides the Status Indicators of the Invoke-WebRequest Calls later on
        $ProgressPreference = 'SilentlyContinue'

        # Assembling the Configuration String, which is the SCEP URL in this Case
        If ($UseSSL)
            { $Protocol = "https" }
        Else 
            { $Protocol = "http" }

        If ($Port)
            { $PortString = ":$($Port)" }
        Else
            { $PortString = [String]::Empty }

        $ConfigString = "$($Protocol)://$($ComputerName)$($PortString)/$($Suffix)/pkiclient.exe"

        Write-Verbose -Message "Configuration String: $ConfigString"

        # SCEP GetCACert Operation
        Try {
            $GetCACert = (Invoke-WebRequest -uri "$($ConfigString)?operation=GetCACert" -UseBasicParsing).Content

            # Decoding the CMS (PKCS#7 Message that was returned from the NDES Server)
            $Pkcs7CaCert = New-Object System.Security.Cryptography.Pkcs.SignedCms
            $Pkcs7CaCert.Decode($GetCACert)
        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return
        }

    }

    process {
        # Ensuring we work with Elevation when messing with the Computer Certificate Store
        If ($Import.IsPresent) {
            
            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) since using the Machine Context!" 
                return
            }
        }

        # Skip pipeline processing if the preparation steps failed
        If (-not $Pkcs7CaCert.Certificates) { return }

        <#
            Identify the Root CA Certificate that was delivered with the Chain
            https://tools.ietf.org/html/rfc5280#section-6.1
            A certificate is self-issued if the same DN appears in the subject and issuer fields 
        #>
        $RootCaCert = $Pkcs7CaCert.Certificates | Where-Object { $_.Subject -eq $_.Issuer }

        $certnum = 0

        Try {
            If ($Import.IsPresent) {
                $X509Store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList ("AuthRoot", [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            }

            $CertificateRequestAgentOid = New-Object Security.Cryptography.Oid "1.3.6.1.4.1.311.20.2.1" # Certificate Request Agent
            $Pkcs7CaCert.Certificates | Where-Object { 
                $isRA = $_.EnhancedKeyUsageList | Where ObjectId -eq $CertificateRequestAgentOid.Value 
                If (-not $isRA) {
                    return $True
                }
            } | ForEach-Object { 
                If ($Export.IsPresent) {
                    $outputPath = "$($CertificateFolder)\CA-cert-$($certnum).crt" 
                    $base64CertText = [System.Convert]::ToBase64String($_.RawData, "InsertLineBreaks")
                    $out = "-----BEGIN CERTIFICATE-----`n$($base64CertText)`n-----END CERTIFICATE-----"
                    [System.IO.File]::WriteAllText($outputPath, $out)
                    Write-Output "$($_.Subject) written to $($outputPath)"
                }
                If ($Import.IsPresent) {
                    $X509Store.Add($_)
                    Write-Output "$($_.Subject) imported to Cert:$($X509Store.Location)\$($X509Store.Name)"
                }
            }

        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return
        }
    }

    end {}
}