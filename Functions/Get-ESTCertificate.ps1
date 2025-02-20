Function Get-ESTCertificate {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True, ValuefromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateRequest,

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
        $Suffix = ".well-known/est",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Switch]
        $Reenroll
    )

    begin {
        
        # This hides the Status Indicators of the Invoke-WebRequest Calls later on
        $ProgressPreference = 'SilentlyContinue'
    }

    process {

        <#
        RFC 7030 4.2

        EST clients request a certificate from the EST server with an HTTPS
        POST using the operation path value of "/simpleenroll". EST clients
        request a renew/rekey of existing certificates with an HTTP POST
        using the operation path value of "/simplereenroll". EST servers
        MUST support the /simpleenroll and /simplereenroll functions.

        It is RECOMMENDED that a client obtain the current CA certificates,
        as described in Section 4.1, before performing certificate request
        functions. This ensures that the client will be able to validate the
        EST server certificate. The client MUST authenticate the EST server
        as specified in Section 3.3.1 if certificate-based authentication is
        used or Section 3.3.3 if the optional certificate-less authentication
        is used. The client MUST verify the authorization of the EST server
        as specified in Section 3.6.
        #>

        if ($Reenroll.IsPresent) {
            $Operation = "simplereenroll"
        }
        else {
            $Operation = "simpleenroll"
        }

        <#
        RFC 7030 4.2.1
        When HTTPS POSTing to /simpleenroll, the client MUST include a Simple PKI Request as specified in CMC [RFC5272], Section 3.1 (i.e., a PKCS#10 Certification Request [RFC2986]).
        The HTTP content-type of "application/pkcs10" is used here. The format of the message is as specified in [RFC5967] with a Content-Transfer-Encoding of "base64" [RFC2045].
        #>

        $Headers = @{
            "Content-Type" = "application/pkcs10"
            "Content-Transfer-Encoding" = "base64"
        }

        if ($Password) {

            <#
            RFC 7030 3.2.3
            A client MAY set the username to the empty string ("") if it is presenting a password that is not associated with a username.
            #>

            $Username = $Credential.UserName,
            $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
            )

            $EncodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Username):$($Password)"))

            $Headers.Add("Authorization", "Basic $EncodedCredentials")

        }

        $Response = Invoke-WebRequest -Method POST -Uri "https://${ComputerName}:${Port}/${Suffix}/${Operation}" -Headers $Headers -Body $CertificateRequest -UseBasicParsing

        <#
        RFC 7030 4.2.3
        If the enrollment is successful, the server response MUST contain an HTTP 200 response code with a content-type of "application/pkcs7-mime".
        #>

        # Error 401: Unauthorized The server was unable to authorize the request. - e.g. when credentials are wrong
        # Error 400: Bad Request Invalid or corrupted pkcs10 request. - e.g when input is no valid CSR
        if ($Response.StatusCode -ne 200) {
            $Response
            return
        }

        <#
        A successful response MUST be a certs-only CMC Simple PKI Response, as defined in [RFC5272], containing only the certificate that was
        issued. The HTTP content-type of "application/pkcs7-mime" with an smime-type parameter "certs-only" is used, as specified in [RFC5273].
        #>

        if ($Response.Headers["Content-Type"] -ne "application/pkcs7-mime; smime-type=certs-only") {
            Write-Error "Got response as $($Response.Headers["Content-Type"]), which is not compliant to RFC 7030."
            return
        }

        $SimplePkiResponse = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $SimplePkiResponse.Decode([Convert]::Frombase64String([System.Text.Encoding]::ASCII.GetString($Response.Content).Replace("`n", [String]::Empty)))
        $SimplePkiResponse.Certificates
    }
}