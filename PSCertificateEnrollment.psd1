﻿#
# Module manifest for module 'PSCertificateEnrollment'
#
# Generated by: Uwe Gradenegger
#
# Generated on: 11.11.2020
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'PSCertificateEnrollment.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.11'

    # Supported PSEditions.
    # https://docs.microsoft.com/en-us/powershell/scripting/gallery/concepts/module-psedition-support
    CompatiblePSEditions = @('Desktop')

    # ID used to uniquely identify this module
    GUID = '74768cbe-add9-4b55-b060-a9461a16e98d'

    # Author of this module
    Author = 'Uwe Gradenegger'

    # Company or vendor of this module
    CompanyName = 'Uwe Gradenegger'

    # Copyright statement for this module
    Copyright = '(c) 2020-2023 Uwe Gradenegger. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Extends the Built-In PKIClient Module. Building Certificate Signing Requests, Certificate Enrollment via the Microsoft Network Device Enrollment Service (NDES) via the Simple Certificate Enrollment Protocol (SCEP).'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = 'v4.6'

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Get-NDESOTP',
        'Get-NDESCertificate',
        'Get-NDESCACertificate',
        'Get-KeyStorageProvider',
        'Get-IssuedCertificate',
        'New-CertificateRequest',
        'New-SignedCertificateRequest',
        'Install-IssuedCertificate',
        'Undo-CertificateArchival',
        'Get-RemoteDesktopCertificate',
        'Set-RemoteDesktopCertificate',
        'Invoke-AutoEnrollmentTask'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # The primary categorization of this module (from the TechNet Gallery tech tree).
            Category = "Scripting Techniques"

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('powershell','scep','ndes','pki','adcs','certificate','x509')

            # A URL to the license for this module.
            LicenseUri = 'https://raw.githubusercontent.com/Sleepw4lker/PSCertificateEnrollment/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/Sleepw4lker/PSCertificateEnrollment'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}