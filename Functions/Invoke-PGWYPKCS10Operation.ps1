function Invoke-PGWYPKCS10Operation {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Uri,

        [Parameter(Mandatory=$True)]
        [Byte[]]
        $CertificateRequest,

        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $ClientCertificate,

        [Parameter(Mandatory=$False)]
        [Byte[]]
        $SignedData
    )

    # This hides the Status Indicators of the Invoke-WebRequest Calls later on
    $ProgressPreference = "SilentlyContinue"

    $Boundary = [System.Guid]::NewGuid().ToString()

    $Body = New-Object -TypeName System.Collections.ArrayList

    $Body.AddRange(
        @(
        "--$Boundary",
        "Content-Type: application/pkcs10; charset=utf-8",
        "Content-Disposition: form-data; name=`"pkcs10`"`r`n",
        [System.Convert]::ToBase64String($CertificateRequest, [Base64FormattingOptions]::InsertLineBreaks)
        )
    )

    if ($SignedData) {

        $Body.AddRange(
            @(
            "--$Boundary",
            "Content-Type: application/octet-stream; charset=utf-8",
            "Content-Disposition: form-data; name=`"signature`"`r`n",
            [System.Convert]::ToBase64String($SignedData, [Base64FormattingOptions]::InsertLineBreaks)
            )
        )
    }
    
    $Body.Add("--$Boundary--`r`n")

    $Arguments = @{
        Uri = $Uri
        Headers = @{
            "Accept" = "application/pkix-cert"
            "Content-Type" = "multipart/form-data; boundary=$Boundary"
        }
        Method = "POST"
        Body = ($Body -join "`r`n")
        Certificate = $ClientCertificate
    }

    return Invoke-WebRequest @Arguments
}