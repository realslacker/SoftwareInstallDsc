@{

    # Version number of this module.
    moduleVersion     = '0.5'

    # ID used to uniquely identify this module
    GUID              = '18d66347-1ee7-411e-adce-a3c6fee8ddad'

    # Author of this module
    Author            = 'Shannon Graybrook'

    # Company or vendor of this module
    CompanyName       = 'graybrook.io'

    # Copyright statement for this module
    Copyright         = 'Copyright Shannon Graybrook. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'DSC resources for configuring software installation.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion        = '4.0'

    # Functions to export from this module
    FunctionsToExport = @()

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport   = @()

    # DSC resources to export from this module
    DscResourcesToExport  = @( 'SoftwareInstall' )

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{

        PSData = @{

            # Set to a prerelease string value if the release should be a prerelease.
            Prerelease   = ''

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @( 'DesiredStateConfiguration', 'DSC', 'DSCResource', 'Software', 'Install' )

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/realslacker/DSC_xSoftwareInstallResource/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/realslacker/SoftwareInstallDsc'

            # A URL to an icon representing this module.
            # IconUri      = 'https://dsccommunity.org/images/DSC_Logo_300p.png'

            # ReleaseNotes of this module
            ReleaseNotes = ''
            
        } # End of PSData hashtable
    } # End of PrivateData hashtable
}
