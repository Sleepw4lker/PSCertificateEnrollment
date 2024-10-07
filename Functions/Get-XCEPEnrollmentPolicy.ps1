<#
    .SYNOPSIS
    Retrieves the raw XML data from an MS-XCEP Server Implementation
#>
Function Get-XCEPEnrollmentPolicy { 

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
        $Suffix = "ADPolicyProvider_CEP_Kerberos"
    )

    begin {

        # This hides the Status Indicators of the Invoke-WebRequest Calls later on
        $ProgressPreference = 'SilentlyContinue'

    }

    process {

        $Uri = "https://$($ComputerName):${Port}/$($Suffix)/service.svc/CEP/"

        $Headers = @{
            "Content-Type" = "application/soap+xml; charset=utf-8"
        }

        $Body = "
        <s:Envelope xmlns:a=`"http://www.w3.org/2005/08/addressing`" xmlns:s=`"http://www.w3.org/2003/05/soap-envelope`">
        <s:Header>
            <a:Action s:mustUnderstand=`"1`">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies</a:Action>
            <a:MessageID>urn:uuid:$((New-Guid).Guid)</a:MessageID>
            <a:To s:mustUnderstand=`"1`">$Uri</a:To>
        </s:Header>
        <s:Body>
            <GetPolicies xmlns=`"http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy`">
                <client>
                    <lastUpdate a:nil=`"true`" xmlns:a=`"http://www.w3.org/2001/XMLSchema-instance`"/>
                    <preferredLanguage>en-US</preferredLanguage>
                </client>
                <requestFilter>
                    <policyOIDs a:nil=`"true`" xmlns:a=`"http://www.w3.org/2001/XMLSchema-instance`"/>
                    <clientVersion>6</clientVersion>
                    <serverVersion>0</serverVersion>
                </requestFilter>
            </GetPolicies>
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