<#
    .SYNOPSIS
    Creates a Subject Alternative Name (SAN) extension for certificate requests.

    .DESCRIPTION
    This function creates a CX509ExtensionAlternativeNames COM object containing
    the specified Subject Alternative Names (UPN, Email, DNS, and IP addresses).
    This extension can then be added to certificate requests.

    .PARAMETER Upn
    Specifies one or more User Principal Names to be written into the Subject Alternative Name extension.

    .PARAMETER Email
    Specifies one or more E-Mail addresses (RFC 822) to be written into the Subject Alternative Name extension.

    .PARAMETER Dns
    Specifies one or more DNS names to be written into the Subject Alternative Name extension.

    .PARAMETER IP
    Specifies one or more IP Addresses to be written into the Subject Alternative Name extension.

    .OUTPUTS
    Returns a CX509ExtensionAlternativeNames COM object ready to be added to a certificate request.

    .EXAMPLE
    $sanExtension = New-SanExtension -Dns "example.com", "www.example.com" -Email "admin@example.com"
    $CertificateRequestPkcs10.X509Extensions.Add($sanExtension)

    .EXAMPLE
    $sanExtension = New-SanExtension -IP "192.168.1.100" -Upn "user@domain.com"
    $CertificateRequestPkcs10.X509Extensions.Add($sanExtension)
#>
Function New-SanExtension {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [mailaddress[]]
        $Upn,

        [Alias("RFC822Name")]
        [Alias("E-Mail")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [mailaddress[]]
        $Email,

        [Alias("DnsName")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Dns,

        [Alias("IPAddress")]
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [System.Net.IPAddress[]]
        $IP
    )

    process {

        # Return null if no SAN parameters are provided
        If (-not ($Upn -or $Email -or $Dns -or $IP)) {
            return $null
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionalternativenames
        $SubjectAlternativeNamesExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
        $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames

        # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx

        Foreach ($Entry in $Upn) {
        
            $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
            $AlternativeNameObject.InitializeFromString(
                $AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, 
                $Entry
            )
            $Sans.Add($AlternativeNameObject)
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

        }

        Foreach ($Entry in $Email) {
        
            $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
            $AlternativeNameObject.InitializeFromString(
                $AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME, 
                $Entry
            )
            $Sans.Add($AlternativeNameObject)
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

        }

        Foreach ($Entry in $Dns) {
        
            $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
            $AlternativeNameObject.InitializeFromString(
                $AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME,
                $Entry
            )
            $Sans.Add($AlternativeNameObject)
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

        }

        Foreach ($Entry in $IP) {

            $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
            $AlternativeNameObject.InitializeFromRawData(
                $AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS,
                $EncodingType.XCN_CRYPT_STRING_BASE64,
                [Convert]::ToBase64String($Entry.GetAddressBytes())
            )
            $Sans.Add($AlternativeNameObject)
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))

        }
        
        $SubjectAlternativeNamesExtension.Critical = $True
        $SubjectAlternativeNamesExtension.InitializeEncode($Sans)

        return $SubjectAlternativeNamesExtension
    }
}