function Clear-XCEPEnrollmentPolicyCache {

    [cmdletbinding()]
    param(
        [Alias("Machine")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext = $False
    )

    process {

        if ($MachineContext.IsPresent) {

            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }

            $Path = "$env:ProgramData\Microsoft\Windows\X509Enrollment"
        }
        else {
            
            $Path = "$env:USERPROFILE\AppData\Local\Microsoft\Windows\X509Enrollment"
        }
        
        Get-ChildItem -Path $Path | ForEach-Object -Process {
            Write-Verbose -Message "Deleting $($_.FullName)"
            $_ | Remove-Item -Force
        }

    }

}