function Test-IsElevated {

    # Its own function, so tests can mock the elevation check
    [CmdletBinding()]
    [OutputType([Bool])]
    param()

    ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator"
    )
}
