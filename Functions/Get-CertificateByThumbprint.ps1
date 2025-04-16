function Get-CertificateByThumbprint {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Thumbprint
    )

    foreach ($StoreName in @("CurrentUser", "LocalMachine")) {

        $Certificate = Get-ChildItem -Path "Cert:\$StoreName\My\$Thumbprint" -ErrorAction SilentlyContinue
        if ($Certificate) {
            return $Certificate
        }
    }
    
    throw "Certificate $Thumbprint not found!"
}