Function Get-ESTCACertificates {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [String]
        $ComputerName,

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,65535)]
        [Int]
        $Port = 443,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Suffix = ".well-known/est"
    )

    begin {
        
        # This hides the Status Indicators of the Invoke-WebRequest Calls later on
        $ProgressPreference = "SilentlyContinue"
    }

    process {

        $Response = Invoke-WebRequest -Uri "https://${ComputerName}:${Port}/${Suffix}/cacerts" -UseBasicParsing
      
        if ($Response.StatusCode -ne 200) {
            $Response
            return
        }

        if ($Response.Headers["Content-Type"] -ne "application/pkcs7-mime") {
            Write-Error "Got response as $($Response.Headers["Content-Type"]), which is not compliant to RFC 7030."
            return
        }

        <#
        RFC 7030 4.1.3.
        A successful response MUST be a certs-only CMC Simple PKI Response,
        as defined in [RFC5272], containing the certificates described in the
        following paragraph. The HTTP content-type of "application/pkcs7-mime" is used. 
        #>

        <#
        RFC 5272 4.1
        Clients MUST be able to process the Simple PKI Response. The Simple
        PKI Response consists of a SignedData with no EncapsulatedContentInfo and no SignerInfo.
        #>

        $SimplePkiResponse = New-Object -TypeName Security.Cryptography.Pkcs.SignedCms
        $SimplePkiResponse.Decode([Convert]::Frombase64String([System.Text.Encoding]::ASCII.GetString($Response.Content).Replace("`n", [String]::Empty)))
        $SimplePkiResponse.Certificates
    }
}