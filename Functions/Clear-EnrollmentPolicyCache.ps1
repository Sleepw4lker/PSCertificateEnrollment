function Clear-EnrollmentPolicyCache {

    [cmdletbinding()]
    [Alias("Clear-XCEPEnrollmentPolicyCache")]
    param(
        [Alias("Machine")]
        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext
    )

    if ($MachineContext.IsPresent) {

        If (-not (Test-IsElevated)) {
            Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
            return
        }

        $Path = "$env:ProgramData\Microsoft\Windows\X509Enrollment"
    }
    else {
        
        $Path = "$env:USERPROFILE\AppData\Local\Microsoft\Windows\X509Enrollment"
    }
    
    # No cache folder yet means there is nothing to clear
    if (-not (Test-Path -Path $Path)) {
        return
    }

    Get-ChildItem -Path $Path | ForEach-Object -Process {
        Write-Verbose -Message "Deleting $($_.FullName)"
        $_ | Remove-Item -Force
    }
}