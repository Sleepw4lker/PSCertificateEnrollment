Function Test-KSPAvailability {

    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    process {

        # Seems that there is no Enumerate Method or the like to test the actual presence of a CSP/KSP.
        # Thus we simply try to initialize with the given KSP name.
        # If this does not fail, we can assume that KSP is installed on the System.

        # https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/master/security/certservices/certenroll/createsimplecertrequest/CreateSimpleCertRequest.cs
        $CspInformationObject = New-Object -ComObject X509Enrollment.CCspInformation

        Try {
            $CspInformationObject.InitializeFromName($Name)
            return $True
        }
        Catch {
            return $False
        }
        Finally {
            # Releasing the COM Object after Usage
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($CspInformationObject)
        }
    }
}