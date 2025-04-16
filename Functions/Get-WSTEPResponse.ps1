<#
    .SYNOPSIS
    Retrieves the raw XML data from an MS-WSTEP Server Implementation
#>

Function Get-WSTEPResponse {

    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$True,
            ValuefromPipeline=$True
            )]
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
        $CertificateTemplate,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Suffix = "Policy/Kerberos" #TODO
    )

    begin {

        # This hides the Status Indicators of the Invoke-WebRequest Calls later on
        $ProgressPreference = "SilentlyContinue"

    }

    process {

        $Uri = "https://$($ComputerName)/$($Suffix)/service.svc/CES"

        $Headers = @{
            "Content-Type" = "application/soap+xml; charset=utf-8"
        }

        If ($CertificateTemplate) {

            $AdditionalContext = "<ContextItem Name=`"CertificateTemplate`"><Value>$CertificateTemplate</Value></ContextItem>"

        }
        else {
            $AdditionalContext = [String]::Empty
        }

        $CertificateRequest = $CertificateRequest -replace "-----.*-----", "" -replace "`n","" -replace "`r",""

        $Body = "<s:Envelope xmlns:a=`"http://www.w3.org/2005/08/addressing`" xmlns:s=`"http://www.w3.org/2003/05/soap-envelope`">
        <s:Header>
            <a:Action s:mustUnderstand=`"1`">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
            <a:MessageID>urn:uuid:$((New-Guid).Guid)</a:MessageID>
            <a:To s:mustUnderstand=`"1`">$Uri</a:To>
        </s:Header>
        <s:Body>
            <RequestSecurityToken PreferredLanguage=`"en-US`" xmlns=`"http://docs.oasis-open.org/ws-sx/ws-trust/200512`">
            <TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>
            <RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType>
            <BinarySecurityToken ValueType=`"http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10`" EncodingType=`"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary`" a:Id=`"`" xmlns:a=`"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd`" xmlns=`"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd`">$CertificateRequest</BinarySecurityToken>
            <AdditionalContext xmlns=`"http://schemas.xmlsoap.org/ws/2006/12/authorization`">$AdditionalContext<ContextItem Name=`"ccm`"><Value>$(([System.Net.Dns]::GetHostByName($env:computerName)).HostName)</Value></ContextItem></AdditionalContext>
            </RequestSecurityToken>
        </s:Body>
        </s:Envelope>"

        $Arguments = @{
            Uri = $Uri
            UseBasicParsing = $True
            Method = "POST"
            Body = $Body
            UseDefaultCredentials = $True
            Headers = $Headers
        }

        $Response = Invoke-WebRequest @Arguments

        if ($Response.StatusCode -eq 200) {
            $Response.Content
        }

    }

}