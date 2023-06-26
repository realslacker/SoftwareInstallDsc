using namespace System.Diagnostics
using namespace System.IO
using namespace System.Text
using namespace System.Net
using namespace System.Net.Security
using namespace System.Security.Cryptography
using namespace System.Management.Automation


$Script:PackageCacheLocation = "$env:ProgramData\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache\DSC_SoftwareInstallResource"


function Invoke-SoftwareInstallCommand {
    
    [CmdletBinding( SupportsShouldProcess = $true )]
    param(

        [Parameter( Mandatory = $true )]
        [System.String]
        $Installer,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $InstallCommand,

        # Return codes 1641 and 3010 indicate success when a restart is requested per installation
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.UInt32[]]
        $ReturnCode = @( 0, 1641, 3010 ),

        [Parameter()]
        [System.String]
        $LogPath,

        [Parameter()]
        [System.Boolean]
        $IgnoreReboot = $false,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $RunAsCredential,

        [Parameter()]
        [System.UInt32]
        $TimeoutSeconds

    )

    # not install string provided, we're going to assume a bare command for .EXE and default .MSI command
    if ( [string]::IsNullOrEmpty( $InstallCommand ) ) {

        $Extension = [path]::GetExtension( $Installer )

        if ( $Extension -eq '.msi' ) {

            $InstallCommand = '"%windir%\System32\msiexec.exe" /I "{0}" /QN'

            if ( $LogPath -and ( Test-LogFileIsWritable @PSBoundParameters ) ) {

                $InstallCommand += ' /log "{1}"'

            }

        } else {

            $InstallCommand = '"{0}"'

        }
    
    }

    # escape any curly brace that is not explicitly '{0}', '{1}', etc..
    $CommandLine = $CommandLine -replace '{(?!\d})', '{{' -replace '(?<!{\d)}', '}}'

    # interpolate the Installer, and Log Path in the command
    $CommandLine = $CommandLine -f $Installer, $LogPath
    
    if ( $PSCmdlet.ShouldProcess( ( 'Run command line: {0}' -f $CommandLine ), $null, $null ) ) {
            
        $StartProcessSplat = ConvertFrom-CommandLine $CommandLine
        
        if ( $RunAsCredential ) {
            $StartProcessSplat.Credential = $RunAsCredential
        }

        $Process = Start-Process @StartProcessSplat -PassThru

        $InstallTimeout = $null
        
        $WaitProcessSplat = @{
            ErrorAction   = 'SilentlyContinue'
            ErrorVariable = 'InstallTimeout'
        }

        if ( $TimeoutSeconds ) {
            $WaitProcessSplat.Timeout = $TimeoutSeconds
        }

        $Process | Wait-Process @WaitProcessSplat

        if ( $InstallTimeout ) {

            $Process | Stop-Process -Force -ErrorAction Stop
            $ExitCode = 1

        } else {

            $ExitCode = $Process.ExitCode

        }

        if ( -not $IgnoreReboot -and $ExitCode -eq 3010 ) {

            $global:DSCMachineStatus = 1

        }

        if ( $ExitCode -notin $ValidReturnCodes ) {

            Write-Error ( 'Could not {0} the package.' -f $CommandTypeVerb ) -ErrorAction Stop

        } else {

            Write-Verbose ( 'Package {0} was completed.' -f $CommandTypeVerb )

        }
    
    }
    
}

function Invoke-CommandLine {

    [CmdletBinding( SupportsShouldProcess = $true )]
    param(

        [Parameter( Mandatory = $true )]
        [System.String]
        $CommandLine,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $RunAsCredential,

        [Parameter()]
        [System.Nullable[System.UInt32]]
        $TimeoutSeconds
    )

    $Command = $null

    # if the command line does not contain any quote characters we have to try to figure out the file path
    if ( $CommandLine.IndexOf('"') -eq -1 -and $CommandLine.IndexOf("'") -eq -1 ) {

        # first we try to get the whole command line
        $CommandName = $CommandLine
        $Command = Get-Command -CommandType Application -Name $CommandName -ErrorAction SilentlyContinue

        # if that didn't work we try to split the command on the first space
        if ( -not $Command ) {
            $CommandName = $CommandLine.Split(' ')[0]
            $Command = Get-Command -CommandType Application -Name $CommandName -ErrorAction SilentlyContinue
        }

    }
    
    # if the command line does contain quotes then the command should either be surrounded by quotes or the
    # first string without spaces
    else {

        $CommandName = $CommandLine -replace '^([''"])(?<CommandName>[^\1]+)\1.*|^(?<CommandName>\S+).*', '${CommandName}'
        $Command = Get-Command -CommandType Application -Name $CommandName -ErrorAction SilentlyContinue

    }

    # if it still does not resolve we cannot parse the command line
    if ( -not $Command ) {
        throw 'Could not parse command.'
    }

    # start building the Splat to return
    $CommandSplat = @{}
    $CommandSplat.FilePath = $Command.Source | Select-Object -First 1

    # now we start parsing out the arguments
    # if there are spaces there are params
    $CommandEndPos = $CommandLine.IndexOf($CommandName) + $CommandName.Length
    $NextSpacePos = $CommandLine.IndexOf( ' ', $CommandEndPos )
    if ( $NextSpacePos -gt 0 ) {
        $CommandSplat.ArgumentList = $CommandLine.Substring( $NextSpacePos ).Trim()
    }

    if ( $PSCmdlet.ShouldProcess( ( 'Run command line: {0}' -f $CommandLine ), $null, $null ) ) {
    
        $Process = Start-Process @CommandSplat -PassThru
        
        $CommandTimeout = $null
        
        $WaitProcessSplat = @{}
        $WaitProcessSplat.ErrorVariable = 'CommandTimeout'
        $WaitProcessSplat.ErrorAction = 'SilentlyContinue'
        
        if ( $TimeoutSeconds ) {
            $WaitProcessSplat.Timeout = $TimeoutSeconds
        }
        
        $Process | Wait-Process @WaitProcessSplat

        if ( $CommandTimeout ) {
            $Process | Stop-Process -Force -ErrorAction Continue
            return 1
        } else {
            return $Process.ExitCode
        }

    }

}


function Invoke-SoftwareInstallerDownload {
    <#
    .SYNOPSIS
        Download a file from the web.
    .DESCRIPTION
        Download a file from the web using .NET classes instead of Invoke-WebRequest for better portability.
    .NOTES
        Inspired by similar functions in xPSDesiredStateConfiguration and chocolatey
    .LINK
        https://github.com/dsccommunity/xPSDesiredStateConfiguration/blob/9940d6bd5b839773ffc0427047598ef9cb5693f0/source/DSCResources/DSC_xPackageResource/DSC_xPackageResource.psm1#L498
    .LINK
        https://github.com/chocolatey/choco/blob/develop/src/chocolatey.resources/helpers/functions/Get-ChocolateyWebFile.ps1
    #>
    [CmdletBinding( DefaultParameterSetName = 'NoCredential_ProxyNoCredential' )]
    param(
    
        # Download URI
        [Parameter( Mandatory, Position = 0 )]
        [uri]
        $Uri,

        # Where to save the file
        [Parameter()]
        [string]
        $OutputFolder = $env:TEMP,

        # What to name the downloaded file
        [Parameter()]
        [string]
        $FileName,

        # Callback function to validate server certificate is valid
        [Parameter()]
        [string]
        $ServerCertificateValidationCallback,

        [Parameter( ParameterSetName = 'Credential_ProxyNoCredential', Mandatory )]
        [Parameter( ParameterSetName = 'Credential_ProxyCredential', Mandatory )]
        [Parameter( ParameterSetName = 'Credential_ProxyDefaultCredential', Mandatory )]
        [pscredential]
        $Credential,

        [Parameter( ParameterSetName = 'DefaultCredential_ProxyNoCredential', Mandatory )]
        [Parameter( ParameterSetName = 'DefaultCredential_ProxyCredential', Mandatory )]
        [Parameter( ParameterSetName = 'DefaultCredential_ProxyDefaultCredential', Mandatory )]
        [switch]
        $UseDefaultCredential,

        [Parameter( ParameterSetName = 'NoCredential_ProxyNoCredential' )]
        [Parameter( ParameterSetName = 'Credential_ProxyNoCredential' )]
        [Parameter( ParameterSetName = 'DefaultCredential_ProxyNoCredential' )]
        [Parameter( ParameterSetName = 'NoCredential_ProxyCredential', Mandatory )]
        [Parameter( ParameterSetName = 'Credential_ProxyCredential', Mandatory )]
        [Parameter( ParameterSetName = 'DefaultCredential_ProxyCredential', Mandatory )]
        [Parameter( ParameterSetName = 'NoCredential_ProxyDefaultCredential', Mandatory )]
        [Parameter( ParameterSetName = 'Credential_ProxyDefaultCredential', Mandatory )]
        [Parameter( ParameterSetName = 'DefaultCredential_ProxyDefaultCredential', Mandatory )]
        [uri]
        $Proxy,

        [Parameter( ParameterSetName = 'NoCredential_ProxyCredential', Mandatory )]
        [Parameter( ParameterSetName = 'Credential_ProxyCredential', Mandatory )]
        [Parameter( ParameterSetName = 'DefaultCredential_ProxyCredential', Mandatory )]
        [pscredential]
        $ProxyCredential,

        [Parameter( ParameterSetName = 'NoCredential_ProxyDefaultCredential', Mandatory )]
        [Parameter( ParameterSetName = 'Credential_ProxyDefaultCredential', Mandatory )]
        [Parameter( ParameterSetName = 'DefaultCredential_ProxyDefaultCredential', Mandatory )]
        [switch]
        $ProxyUseDefaultCredential,

        # Force download and overwrite existing file
        [switch]
        $Force,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams
    
    )

    $WebFileTypes = '.php*', '.asp*', '.jsp*'

    $CredentialType, $ProxyCredentialType = $PSCmdlet.ParameterSetName.Split('_')

    Write-Verbose 'Beginning file download.'
    Write-Verbose ( 'Source: {0}' -f $Uri )

    try {

        Write-Verbose 'Resolving output folder.'

        $OutputFolder = $OutputFolder | Resolve-Path | Convert-Path

        if ( -not( Test-Path -Path $OutputFolder -PathType Container ) ) {
            throw ( 'Output folder does not exist: {0}' -f $OutputFolder )
        }

        Write-Verbose 'Creating web request.'

        switch -Wildcard ( $Uri.Scheme ) {
            'http*' { [HttpWebRequest]$WebRequest   = [WebRequest]::Create($Uri) }
            'ftp*'  { [FtpWebRequest]$WebRequest    = [WebRequest]::Create($Uri) }
            'file'  { [FileWebRequest]$WebRequest   = [WebRequest]::Create($Uri) }
            default { throw ( 'Protocol {0} not supported.' -f $Uri.Scheme ) }
        }

        if ( $_ -match '^(ht|f)tp$' ) {
            Write-Verbose -Message 'Setting authentication level.'
            $WebRequest.AuthenticationLevel = [AuthenticationLevel]::None
        }

        if ( $_ -match '^(ht|f)tps$' -and $ServerCertificateValidationCallback ) {
            Write-Verbose -Message 'Assigning user-specified certificate verification callback'
            $WebRequest.ServerCertificateValidationCallBack = [scriptblock]::Create( $ServerCertificateValidationCallback )
        }

        if ( $_ -match '^(ht|f)tps?$' -and $Proxy ) {
            Write-Verbose ( 'Request will use proxy: {0}' -f $Proxy )
            $WebRequest.Proxy = [WebProxy]::new( $Proxy )
            switch ( $ProxyCredentialType ) {
                'ProxyCredential' {
                    Write-Verbose 'Proxy will use supplied credentials'
                    $WebRequest.Proxy.Credentials = $Credential
                }
                'ProxyDefaultCredential' {
                    Write-Verbose 'Proxy will use default credentials.'
                    $WebRequest.Proxy.Credentials = [CredentialCache]::DefaultCredentials
                }
            }
        }

        switch ( $CredentialType ) {
            'Credential' {
                Write-Verbose 'Will use supplied credentials'
                $WebRequest.Credentials = $Credential
            }
            'DefaultCredential' {
                Write-Verbose 'Will use default credentials.'
                $WebRequest.Credentials = [CredentialCache]::DefaultCredentials
            }
        }

        Write-Verbose ( 'Getting {0} response.' -f $Uri.Scheme )

        switch -Wildcard ( $Uri.Scheme ) {    
            'http*' { [HttpWebResponse]$Response  = $WebRequest.GetResponse() }
            'ftp*'  { [FtpWebResponse]$Response   = $WebRequest.GetResponse() }
            'file'  { [FileWebResponse]$Response  = $WebRequest.GetResponse() }
        }

        Write-Verbose 'Response received.'

        if ( -not $PSBoundParameters.ContainsKey( 'FileName' ) ) {

            Write-Verbose 'No file name supplied, attempting to determine filename from URI.'

            $FileName = Split-Path $Uri.AbsolutePath -Leaf

            $Extension = [path]::GetExtension( $FileName )

            if ( -not $Extension -or $WebFileTypes.Where({ $Extension -like $_ }) ) {
                Write-Verbose 'Detected invalid file name extension.'
                if ( $Uri.Scheme -like 'ftp*' ) {
                    throw 'Invalid file name.'
                }
                
                Write-Verbose 'Checking Content-Disposition header.'
                $FileName = [string]$Response.Headers['Content-Disposition'] -replace '.*filename=' |
                    ForEach-Object { $_.Trim('"''') } |
                    Select-Object -First 1

                if ( -not $FileName ) {
                    throw 'Invalid file name, and no Content-Disposition header from server.'
                }

            }
    
        }

        Write-Verbose ( 'Will use file name: {0}' -f $FileName )

        $OutputPath = Join-Path $OutputFolder $FileName

        if ( -not $Force -and ( Test-Path -Path $OutputPath -PathType Leaf ) ) {

            Write-Verbose ( 'Found existing file: {0}' -f $OutputPath )
            Write-Verbose 'Download aborted.'
        
        } else {

            Write-Verbose ( 'Creating output file: {0}' -f $OutputPath )
            $OutStream = [FileStream]::new( $OutputPath, 'Create' )
        
            Write-Verbose -Message ( 'Getting {0} response stream.' -f $Uri.Scheme )
            $ResponseStream = $Response.GetResponseStream()

            Write-Verbose -Message ( 'Downloading file: {0}' -f $FileName )
            $ResponseStream.CopyTo( $OutStream )
            $ResponseStream.Flush()
            $OutStream.Flush()

        }

    } finally {

        if ( $null -ne $Response ) {
            $Response.Close()
            $Response.Dispose()
        }
        
        if ( $null -ne $ResponseStream ) {
            $ResponseStream.Close()
            $ResponseStream.Close()
        }

        if ( $null -ne $OutStream ) {
            $OutStream.Close()
            $OutStream.Dispose()
        }

        'WebRequest', 'OutStream', 'Response' | ForEach-Object {
            Remove-Variable -Name $_ -ErrorAction SilentlyContinue
        }

    }

    Write-Verbose 'Download complete.'

    Get-Item -Path $OutputPath

}


function Get-UninstallEntry {
    <#
    .SYNOPSIS
        Return uninstall entries matching given parameters.
    .DESCRIPTION
        Return uninstall entries matching given parameters.
    #>
    [CmdletBinding()]
    param(

        # Matches the DisplayName of the uninstall entry
        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name,

        # Matches the Publisher of the uninstall entry
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Publisher,

        # Matches the DisplayVersion of the uninstall entry
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Version,

        # How to compare the given version with the DisplayVersion
        [Parameter()]
        [ValidateSet( 'Any', 'LessThan', 'LessThanOrEqualTo', 'EqualTo', 'GreaterThanOrEqualTo', 'GreaterThan' )]
        [string]
        $VersionComparison = 'EqualTo',

        # How many versions to return, newest to oldest
        [Parameter()]
        [ValidateRange( 1, [uint32]::MaxValue)]
        [uint32]
        $LatestVersions = 1,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams

    )

    Write-Verbose ( 'Searching for products matching ''{0}''.' -f $Name )

    $RegistryLocations = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    ) | Where-Object { Test-Path -Path $_ }
    
    [object[]]$MatchingProducts = Get-ItemProperty -Path $RegistryLocations | ForEach-Object {

        if ( [string]::IsNullOrEmpty( $_.DisplayName ) ) {
            Write-Debug 'Uninstall entry missing DisplayName.'
            return
        }
        if ( [string]::IsNullOrEmpty( $_.DisplayVersion ) ) {
            Write-Debug 'Uninstall entry missing DisplayVersion.'
            return
        }
        if ( [string]::IsNullOrEmpty( $_.UninstallString ) ) {
            Write-Debug 'Uninstall entry missing UninstallString.'
            return
        }
        if ( $_.DisplayName -notlike $Name ) {
            Write-Debug ( 'Uninstall DisplayName ''{0}'' does not match ''{1}''.' -f $_.DisplayName, $Name )
            return
        }
        if ( $Publisher -and $_.Publisher -notlike $Publisher ) {
            Write-Debug ( 'Uninstall Publisher ''{0}'' does not match ''{1}''.' -f $_.Publisher, $Publisher )
            return
        }
        if ( $Version -and $Version -ne 'Any' ) {
            Write-Verbose ( 'Filter for versions {0} {1}.' -f $VersionComparison, $Version )
            [version]$PackageVersion = $_.DisplayVersion
            $VersionComparisonResult = switch ( $VersionComparison ) {
                'Any'                  { $true }
                'LessThan'             { $PackageVersion -lt $Version }
                'LessThanOrEqualTo'    { $PackageVersion -le $Version }
                'EqualTo'              { $PackageVersion -eq $Version }
                'GreaterThanOrEqualTo' { $PackageVersion -ge $Version }
                'GreaterThan'          { $PackageVersion -gt $Version }
            }
            if ( -not $VersionComparisonResult ) {
                Write-Debug ( 'Uninstall DisplayVersion does not match condition {0} when comparing value ''{1}'' to ''{2}''.' -f $VersionComparison, $PackageVersion, $Version )
                return
            }
        }
        
        Write-Verbose ( 'Found matching product ''{0}'' {1} from publisher {2}.' -f $_.DisplayName, $_.DisplayVersion, $_.Publisher )
            
        [pscustomobject]@{
            Name                    = $_.DisplayName
            Publisher               = $_.Publisher
            Version                 = [version]$_.DisplayVersion
            ProductId               = $( try { [guid]$_.PSChildName } catch {} )
            UninstallString         = $_.UninstallString
            QuietUninstallString    = $_.QuietUninstallString
        }
    
    } | Group-Object Name

    if ( $MatchingProducts.Count -gt 1 ) {
        Write-Error 'More than one product returned from search.'
        return
    }

    if ( $MatchingProducts.Count -eq 0 ) {
        Write-Warning 'No matching product was found.'
        return
    }

    return $MatchingProducts[0].Group | Sort-Object { [version]$_.DisplayVersion } -Descending | Select-Object -First $LatestVersions

}


class StringHashResult {

    [ValidateSet( 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160' )]
    [ValidateNotNullOrEmpty()]
    [string] $Algorithm = 'SHA256'

    [ValidateNotNullOrEmpty()]
    [string] $String

    [ValidateNotNullOrEmpty()]
    [string] $Hash

}


function Get-StringHash {
    <#
    .SYNOPSIS
        Generates and MD5 hash for a given string.
    #>
    [OutputType( [StringHashResult] )]
    param(
        
        # String for which MD5 hash should be calculated
        [Parameter( Position = 0, Mandatory )]
        [string]
        $String,

        [ValidateSet( 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160' )]
        [string]
        $Algorithm = 'SHA256'

    )

    if ( -not( $HashAlgorithm = [HashAlgorithm]::Create($Algorithm) ) ) {
        throw ( 'Unsupported hashing algorithm: {0}' -f $Algorithm )
    }

    try {
        [StringHashResult]@{
            Algorithm = $Algorithm
            Hash      = $HashAlgorithm.ComputeHash( [Encoding]::UTF8.GetBytes( $String ) ).ForEach({ '{0:x2}' -f $_ }) -join ''
            String    = $String
        }
    } finally {
        $HashAlgorithm.Dispose()
    }

}


function Get-CacheFolder {
    <#
    .SYNOPSIS
        Create and return the path for a cache folder on the disk.
    .DESCRIPTION
        Create and return the path for a cache folder on the disk. Uses the Name property MD5 hash as the folder name.
    #>
    [CmdletBinding()]
    param(

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams

    )

    $FolderName = Get-StringMD5 $Name
    $FolderPath = Join-Path $Script:PackageCacheLocation $FolderName

    Write-Verbose ( 'Cache folder: {0}' -f $FolderPath )

    if ( Test-Path -Path $FolderPath -PathType Container ) {

        Get-Item -Path $FolderPath -ErrorAction Stop | Convert-Path

    } else {

        New-Item -Path $FolderPath -ItemType Directory -Force -ErrorAction Stop | Convert-Path

    }

}


function Remove-CacheFolder {
    <#
    .SYNOPSIS
        Remove a cache folder on the disk.
    .DESCRIPTION
        Remove a cache folder on the disk. Uses the Name property MD5 hash as the folder name.
    #>
    [CmdletBinding()]
    param(

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams

    )

    $FolderName = Get-StringMD5 $Name
    $FolderPath = Join-Path $Script:PackageCacheLocation $FolderName

    if ( Test-Path -Path $FolderPath -PathType Container ) {

        Write-Verbose ( 'Removing cache folder: {0}' -f $FolderPath )

        Remove-Item -Path $FolderPath -Recurse -Force -ErrorAction Stop

    } else {

        Write-Verbose 'Cache folder does not exist.'

    }

}


function Test-FileHashMatches {
    <#
    .SYNOPSIS
        Checks that the hash of the file at the given path matches the given hash.
    .DESCRIPTION
        Checks that the hash of the file at the given path matches the given hash.
    .NOTES
        Inspired by a similar function in xPSDesiredStateConfiguration
    .LINK
        https://github.com/dsccommunity/xPSDesiredStateConfiguration/blob/9940d6bd5b839773ffc0427047598ef9cb5693f0/source/DSCResources/DSC_xPackageResource/DSC_xPackageResource.psm1#L1507
    #>
    [CmdletBinding()]
    param(

        [Parameter( Mandatory )]
        [string]
        $Path,

        [Parameter( Mandatory )]
        [string]
        $Hash,

        [Parameter()]
        [ValidateSet( 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160' )]
        [string]
        $Algorithm = 'SHA256',

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams

    )

    Write-Verbose ( 'Validating {1} hash for file: {0}' -f $Path, $Algorithm )
    
    $FileHash = Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction 'Stop' |
        Select-Object -ExpandProperty Hash

    if ( $FileHash -ne $Hash ) {

        Write-Verbose ( 'Target Hash: {0}' -f $Hash )
        Write-Verbose ( 'Actual Hash: {0}' -f $FileHash )

        throw 'File hash does not match!'
    
    } else {

        Write-Verbose 'File hash matches.'

    }

}


function Test-FileSignatureMatches {
    <#
    .SYNOPSIS
        Tests that the signature of the file at the given path matches.
    .DESCRIPTION
        Tests that the signature of the file at the given path matches.
    .NOTES
        Inspired by a similar function in xPSDesiredStateConfiguration
    .LINK
        https://github.com/dsccommunity/xPSDesiredStateConfiguration/blob/9940d6bd5b839773ffc0427047598ef9cb5693f0/source/DSCResources/DSC_xPackageResource/DSC_xPackageResource.psm1#L1553
    #>
    [CmdletBinding()]
    param(

        [Parameter( Mandatory )]
        [string]
        $Path,

        # The certificate thumbprint that should match the file's signer certificate
        [Parameter()]
        [string]
        $Thumbprint,

        # The certificate subject that should match the file's signer certificate
        [Parameter()]
        [string]
        $Subject,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams
    
    )

    Write-Verbose -Message ( 'Checking file signing status: {0}' -f $Path )

    $Signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction 'Stop'

    if ( $Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid ) {

        throw ( 'Signature Status: {0}' -f $Signature.Status )
    
    } else {

        Write-Verbose 'File has valid signature.'

    }

    if ( -not [string]::IsNullOrEmpty( $Subject ) ) {
        
        Write-Verbose ( 'Target Subject: {0}' -f $Subject )
        Write-Verbose ( 'Signer Subject: {0}' -f $Signature.SignerCertificate.Subject )
        
        if ( $Signature.SignerCertificate.Subject -notlike $Subject ) {

            throw 'Signer subject does not match.'

        } else {

            Write-Verbose 'Signer subject matches.'

        }
    
    } else {

        Write-Verbose ( 'Signer subject was not checked. Actual value: {0}' -f $Signature.SignerCertificate.Subject )

    }

    if ( -not [string]::IsNullOrEmpty( $Thumbprint ) ) {

        Write-Verbose ( 'Target Thumbprint: {0}' -f $Thumbprint )
        Write-Verbose ( 'Signer Thumbprint: {0}' -f $Signature.SignerCertificate.Thumbprint )

        if ( $Signature.SignerCertificate.Thumbprint -ne $Thumbprint ) {

            throw 'Signer thumbprint does not match.'
    
        } else {

            Write-Verbose 'Signer thumbprint matches.'

        }

    } else {

        Write-Verbose ( 'Signer thumbprint was not checked. Actual value: {0}' -f $Signature.SignerCertificate.Thumbprint )
        
    }

}


function Test-LogFileIsWritable {
    <#
    .SYNOPSIS
        Validate that log file is writable.
    .DESCRIPTION
        Validate that log file is writable by trying to open the file read/write.
    #>
    [CmdletBinding()]
    param(
    
        [Parameter( Mandatory )]
        [string]
        $LogPath,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams
    
    )

    $LogPath = Resolve-Path @PSBoundParameters 2>&1 | ForEach-Object {
        if ( $_ -is [System.Management.Automation.ErrorRecord] ) {
            $_.TargetObject
        } else {
            $_.Path
        }
    }

    $LogExists = Test-Path -Path $LogPath -PathType Leaf

    $IsWriteable = $false

    if ( $LogExists ) {

        try {
            [System.IO.File]::OpenWrite($LogPath).Close()
            $IsWriteable = $true
        } catch {}

    } else {

        try {
            New-Item -Path $LogPath -ItemType File -ErrorAction Stop | Remove-Item
            $IsWriteable = $true
        } catch {}

    }

    Write-Verbose ( 'Log file path: {0}' -f $LogPath )
    Write-Verbose ( 'Log file is writable: {0}' -f $IsWriteable )

    return $IsWriteable

}

