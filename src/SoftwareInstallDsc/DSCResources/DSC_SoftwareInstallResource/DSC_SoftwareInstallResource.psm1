using namespace System.Diagnostics
using namespace System.IO
using namespace System.Text
using namespace System.Net
using namespace System.Net.Security
using namespace System.Security.Cryptography
using namespace System.Management.Automation


$Script:PackageCacheLocation = "$env:ProgramData\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache\DSC_SoftwareInstallResource"

<#
.SYNOPSIS
 Generates and MD5 hash for a given string.
#>
function Get-StringMD5 ( [string]$String ) {
    
    [MD5CryptoServiceProvider]::new().ComputeHash( [Encoding]::UTF8.GetBytes( $Name ) ).ForEach({ '{0:x2}' -f $_ }) -join ''

}

<#
.SYNOPSIS
 Create and return the path for a cache folder on the disk.

.DESCRIPTION
 Create and return the path for a cache folder on the disk. Uses the Name property MD5 hash as the folder name.
#>
function Get-CacheFolder {

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


<#
.SYNOPSIS
 Remove a cache folder on the disk.

.DESCRIPTION
 Remove a cache folder on the disk. Uses the Name property MD5 hash as the folder name.
#>
function Remove-CacheFolder {

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


<#
.SYNOPSIS
 Parse a command line using native command parsing and return a splat compatible with Start-Process.

.DESCRIPTION
 Parse a command line using native command parsing and return a splat compatible with Start-Process.
#>
function ConvertFrom-CommandLine {
    param( [string]$CommandLine )
    function __args { $args }
    $Splat = @{}
    $CommandLine = [environment]::ExpandEnvironmentVariables( $CommandLine ) -replace '([{}$])', '`$1'
    $Splat.FilePath, $Arguments = Invoke-Expression "__args $CommandLine"
    if ( $Arguments ) {
        $Arguments = $Arguments.Trim().ForEach({ if ( $_.IndexOf(' ') -gt 0 ) { '"{0}"' -f $_ } else { $_ } }) -join ' '
        $Splat.ArgumentList = $Arguments
    }
    return $Splat
}


<#
.SYNOPSIS
 Return uninstall entries matching given parameters.

.DESCRIPTION
 Return uninstall entries matching given parameters.

.PARAMETER Name
 Matches the DisplayName of the uninstall entry.

.PARAMETER Publisher
 Matches the Publisher of the uninstall entry.

.PARAMETER Version
 Matches the DisplayVersion of the uninstall entry.

.PARAMETER VersionComparison
 How to compare the given version with the DisplayVersion.

.PARAMETER LatestVersion
 How many versions to return, newest to oldest.

#>
function Get-UninstallEntry {

    [CmdletBinding()]
    param(

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Publisher,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Version,

        [Parameter()]
        [ValidateSet( 'Any', 'LessThan', 'LessThanOrEqualTo', 'EqualTo', 'GreaterThanOrEqualTo', 'GreaterThan' )]
        [string]
        $VersionComparison = 'EqualTo',

        [Parameter()]
        [ValidateRange( 1, [uint32]::MaxValue)]
        [uint32]
        $LatestVersions = 1,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams

    )

    Write-Verbose ( 'Searching for products matching ''{0}'' with versions {1} {2}.' -f $Name, $VersionComparison, $Version )

    $RegistryLocations = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    
    [object[]]$MatchingProducts = Get-ItemProperty -Path $RegistryLocations |
        Where-Object { -not ( [string]::IsNullOrEmpty( $_.DisplayName ) -or [string]::IsNullOrEmpty( $_.DisplayVersion ) -or [string]::IsNullOrEmpty( $_.UninstallString ) ) } |
        Where-Object { $_.DisplayName -like $Name -and ( -not $Publisher -or $_.Publisher -like $Publisher ) } |
        Where-Object {

            if ( [string]::IsNullOrEmpty( $Version ) ) { return $true }

            [version]$PackageVersion = $_.DisplayVersion

            switch ( $VersionComparison ) {
                'Any'                  { $true }
                'LessThan'             { $PackageVersion -lt $Version }
                'LessThanOrEqualTo'    { $PackageVersion -le $Version }
                'EqualTo'              { $PackageVersion -eq $Version }
                'GreaterThanOrEqualTo' { $PackageVersion -ge $Version }
                'GreaterThan'          { $PackageVersion -gt $Version }
            }
        
        } |
        Sort-Object { [version]$_.DisplayVersion } -Descending |
        ForEach-Object {

            Write-Verbose ( 'Found matching product ''{0}'' {1} from publisher {2}.' -f $_.DisplayName, $_.DisplayVersion, $_.Publisher )
            
            [pscustomobject]@{
                Name                    = $_.DisplayName
                Publisher               = $_.Publisher
                Version                 = [version]$_.DisplayVersion
                ProductId               = $( try { [guid]$_.PSChildName } catch {} )
                UninstallString         = $_.UninstallString
                QuietUninstallString    = $_.QuietUninstallString
            }
        
        } |
        Group-Object Name

    if ( $MatchingProducts.Count -eq 0 ) {

        return

    }

    if ( $MatchingProducts.Count -gt 1 ) {

        Write-Error 'More than one product returned from search.' -ErrorAction Stop

    }

    return $MatchingProducts[0].Group | Select-Object -First $LatestVersions

}


<#
.SYNOPSIS
 Asserts that the hash of the file at the given path matches the given hash.

.PARAMETER Path
 The path to the file to check the hash of.

.PARAMETER Hash
 The hash to check against.

.PARAMETER Algorithm
 The algorithm to use to retrieve the file's hash.

.NOTES
 Inspired by a similar function in xPSDesiredStateConfiguration

.LINK
 https://github.com/dsccommunity/xPSDesiredStateConfiguration/blob/9940d6bd5b839773ffc0427047598ef9cb5693f0/source/DSCResources/DSC_xPackageResource/DSC_xPackageResource.psm1#L1507

#>
function Assert-FileHashValid {

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


<#
.SYNOPSIS
 Asserts that the signature of the file at the given path is valid.

.PARAMETER Path
 The path to the file to check the signature of

.PARAMETER Thumbprint
 The certificate thumbprint that should match the file's signer certificate.

.PARAMETER Subject
 The certificate subject that should match the file's signer certificate.

.NOTES
 Inspired by a similar function in xPSDesiredStateConfiguration

.LINK
 https://github.com/dsccommunity/xPSDesiredStateConfiguration/blob/9940d6bd5b839773ffc0427047598ef9cb5693f0/source/DSCResources/DSC_xPackageResource/DSC_xPackageResource.psm1#L1553

#>
function Assert-FileSignatureValid {

    [CmdletBinding()]
    param(

        [Parameter( Mandatory )]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Thumbprint,

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


<#
.SYNOPSIS
 Download a file from the web.

.PARAMETER Uri
 The URI of the file on the web.

.PARAMETER OutputFolder
 Where the file will be output.

.PARAMETER FileName
 Specify a specific output filename.

.PARAMETER ServerCertificateValidationCallback
 Callback function to validate server certificate is valid.

.PARAMETER Credential
 Credential to authenticate for download. Ignored for HTTP or FTP file transfers.

.PARAMETER UseDefaultCredential
 Use default credential to authenticate for download. Ignored for HTTP or FTP file transfers.

.PARAMETER Proxy
 Use a proxy server to download files.

.PARAMETER ProxyCredential
 Credential to authenticate to the proxy server.

.PARAMETER UseDefaultCredential
 Use default credential to authenticate to the proxy server.

.PARAMETER Force
 Force a download.

.NOTES
 Inspired by similar functions in xPSDesiredStateConfiguration and chocolatey

.LINK
 https://github.com/dsccommunity/xPSDesiredStateConfiguration/blob/9940d6bd5b839773ffc0427047598ef9cb5693f0/source/DSCResources/DSC_xPackageResource/DSC_xPackageResource.psm1#L498

.LINK
 https://github.com/chocolatey/choco/blob/develop/src/chocolatey.resources/helpers/functions/Get-ChocolateyWebFile.ps1

#>
function Invoke-WebFileDownload {

    [CmdletBinding( DefaultParameterSetName = 'NoCredential_ProxyNoCredential' )]
    param(
    
        [Parameter( Mandatory, Position = 0 )]
        [uri]
        $Uri,

        [Parameter()]
        [string]
        $OutputFolder = $env:TEMP,

        [Parameter()]
        [string]
        $FileName,

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
            
            'http*' {

                [HttpWebRequest]$WebRequest = [WebRequest]::Create($Uri)

            }

            'ftp*' {

                [FtpWebRequest]$WebRequest = [WebRequest]::Create($Uri)

            }

            default {

                throw ( 'Protocol {0} not supported.' -f $Uri.Scheme )

            }

        }

        if ( $_ -match '(ht|f)tp' ) {
            
            Write-Verbose -Message 'Setting authentication level.'
            $WebRequest.AuthenticationLevel = [AuthenticationLevel]::None

        }

        if ( $_ -match '(ht|f)tps' -and $ServerCertificateValidationCallback ) {

            Write-Verbose -Message 'Assigning user-specified certificate verification callback'
            $WebRequest.ServerCertificateValidationCallBack = [scriptblock]::Create( $ServerCertificateValidationCallback )

        }

        if ( $Proxy ) {

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
            
            'http*' {

                [HttpWebResponse]$Response = $WebRequest.GetResponse()

            }

            'ftp*' {

                [FtpWebResponse]$Response = $WebRequest.GetResponse()

            }

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


<#
.SYNOPSIS
 Copy a file from a local or network share.

.PARAMETER Uri
 The URI of the file.

.PARAMETER OutputFolder
 Where the file will be output.

.PARAMETER FileName
 Specify a specific output filename.

.PARAMETER Credential
 Credential to authenticate for download. Ignored for HTTP or FTP file transfers.

.PARAMETER UseDefaultCredential
 Use default credential to authenticate for download. Ignored for HTTP or FTP file transfers.

.PARAMETER Force
 Force a download.

#>
function Invoke-FileCopy {

    [CmdletBinding()]
    param(
    
        [Parameter( Mandatory, Position = 0 )]
        [uri]
        $Uri,

        [Parameter()]
        [string]
        $OutputFolder = $env:TEMP,

        [Parameter()]
        [string]
        $FileName,

        [Parameter()]
        [pscredential]
        $Credential,

        [Parameter()]
        [switch]
        $UseDefaultCredential,

        [switch]
        $Force,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams
    
    )

    $CredentialSplat = @{}
    if ( $Credential ) { $CredentialSplat.Credential = $Credential }
    if ( $UseDefaultCredential ) { $CredentialSplat.Credential = [CredentialCache]::DefaultCredentials }

    Write-Verbose 'Beginning file copy.'
    Write-Verbose ( 'Source: {0}' -f $Uri.AbsolutePath )

    if ( -not $FileName ) {

        $FileName = Split-Path $Uri.AbsolutePath -Leaf

    }

    Write-Verbose ( 'Will use file name: {0}' -f $FileName )

    $OutputPath = Join-Path $OutputFolder $FileName

    if ( -not $Force -and ( Test-Path -Path $OutputPath -PathType Leaf ) ) {

        Write-Verbose ( 'Found existing file: {0}' -f $OutputPath )
    
    } else {

        if ( $Uri.IsUnc ) {

            Write-Verbose 'Copying file from network path.'

            $SourcePath = Split-Path $Uri.AbsolutePath -Parent
            $SourceFile = Split-Path $Uri.AbsolutePath -Leaf
            
            New-PSDrive -PSProvider FileSystem -Name 'xSoftwareInstallSource' -Root $SourcePath @CredentialSplat -ErrorAction Stop > $null

            try {

                Copy-Item -Path "xSoftwareInstallSource:\$SourceFile" -Destination $OutputPath -ErrorAction Stop

            } finally {

                Remove-PSDrive -Name 'xSoftwareInstallSource'

            }

        } else {

            Write-Verbose 'Copying file from local path.'

            Copy-Item -Path $Uri.AbsolutePath -Destination $OutputPath -ErrorAction Stop

        }

    }

    Write-Verbose 'Copy complete.'

    Get-Item -Path $OutputPath

}


<#
.SYNOPSIS
 Resolve exiting and missing file paths.
#>
function Resolve-PathEx {

    [CmdletBinding( DefaultParameterSetName = 'Path' )]
    param(

        [Parameter(
            ParameterSetName = 'LiteralPath',
            Mandatory = $true,
            Position = 0,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias( 'PSPath' )]
        [string[]]
        $LiteralPath,

        [Parameter(
            ParameterSetName = 'Path',
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]
        $Path,

        [switch]
        $Relative,

        [switch]
        $UseTransaction

    )

    process {

        $PSBoundParameters.ErrorAction = 'Continue'
        $PSBoundParameters.Remove( 'ErrorVariable' ) > $null

        Resolve-Path @PSBoundParameters 2>&1 | ForEach-Object {

            if ( $_ -is [System.Management.Automation.ErrorRecord] ) {

                [pscustomobject]@{
                    Path = $_.TargetObject
                }
            
            } else {
            
                $_
                
            }

        }
    
    }

}


<#
.SYNOPSIS
 Convert paths for existing and non-existant files.
#>
function Convert-PathEx {

    [CmdletBinding( DefaultParameterSetName = 'Path' )]
    param(

        [Parameter(
            ParameterSetName = 'LiteralPath',
            Mandatory = $true,
            Position = 0,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias( 'PSPath' )]
        [string[]]
        $LiteralPath,

        [Parameter(
            ParameterSetName = 'Path',
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]
        $Path,

        [switch]
        $UseTransaction

    )

    process {

        $ErrorParams = @{}

        if ( $PSBoundParameters.ContainsKey( 'ErrorAction' ) ) {

            $ErrorParams.ErrorAction = $PSBoundParameters.ErrorAction
            $PSBoundParameters.ErrorAction = 'Continue'

        }

        if ( $PSBoundParameters.ContainsKey( 'ErrorVariable' ) ) {
    
            $ErrorParams.ErrorVariable = $PSBoundParameters.ErrorVariable
            $PSBoundParameters.Remove( 'ErrorVariable' ) > $null
    
        }

        Convert-Path @PSBoundParameters 2>&1 | ForEach-Object {
    
            if ( $_ -is [System.Management.Automation.ErrorRecord] ) {

                [System.Collections.Generic.List[string]]$Parts = @()
                $TargetPath = $_.TargetObject

                do {
            
                    $Leaf = Split-Path $TargetPath -Leaf
                    $TargetPath = Split-Path $TargetPath -Parent
                    $Parts.Add( $Leaf )

                    if ( -not $TargetPath ) {
                
                        Write-Error @_ @ErrorParams
                        return
                    
                    }

                } until ( $ConvertedPath = Convert-Path $TargetPath -UseTransaction:$UseTransaction -ErrorAction SilentlyContinue )

                $Parts.Insert( 0, $ConvertedPath )

                $Parts -join [IO.Path]::DirectorySeparatorChar
            
            } else {
            
                $_
                
            }

        }

    }

}


<#
.SYNOPSIS
 Validate that log file is writable.
#>
function Test-LogFileIsWritable {

    [CmdletBinding()]
    param(
    
        [Parameter( Mandatory )]
        [string]
        $LogPath,

        [Parameter( ValueFromRemainingArguments = $true, DontShow = $true )]
        $IgnoredParams
    
    )

    $LogPath = Resolve-PathEx -LiteralPath $LogPath | Convert-PathEx

    $LogExists = Test-Path -Path $LogPath -PathType Leaf

    if ( $LogExists ) {

        try {

            [System.IO.File]::OpenWrite($LogPath).Close()
            $Writeable = $true

        } catch {

            $Writeable = $false

        }

    } else {

        try {

            New-Item -Path $LogPath -ItemType File -ErrorAction Stop | Remove-Item
            $Writeable = $true

        } catch {
        
            $Writeable = $false
        
        }

    }

    Write-Verbose ( 'Log file path: {0}' -f $LogPath )
    Write-Verbose ( 'Log file is writable: {0}' -f $Writeable )

    return $Writeable

}


function Get-TargetResource {

    [CmdletBinding( SupportsShouldProcess = $true )]
    param(

        [Parameter()]
        [ValidateSet( 'Present', 'Absent' )]
        [System.String]
        $Ensure = 'Present',

        [Parameter( Mandatory = $true )]
        [ValidateSet( 'MSI', 'EXE' )]
        [System.String]
        $Type,

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [System.String]
        $Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [System.String]
        $Publisher,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Version,

        [Parameter()]
        [ValidateSet( 'Any', 'LessThan', 'LessThanOrEqualTo', 'EqualTo', 'GreaterThanOrEqualTo', 'GreaterThan' )]
        [System.String]
        $VersionComparison = 'EqualTo',

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri,

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
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UninstallCommand,

        # Return codes 1641 and 3010 indicate success when a restart is requested per installation
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.UInt32[]]
        $UninstallReturnCode = @( 0, 3010 ),

        [Parameter()]
        [System.Boolean]
        $UninstallRequiresInstaller = $false,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [System.Boolean]
        $UseDefaultCredential = $false,

        [Parameter()]
        [System.String]
        $Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $ProxyCredential,

        [Parameter()]
        [System.Boolean]
        $ProxyUseDefaultCredential,

        [Parameter()]
        [System.String]
        $LogPath,

        [Parameter()]
        [System.String]
        $Hash,

        [Parameter()]
        [ValidateSet( 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160' )]
        [System.String]
        $Algorithm,

        [Parameter()]
        [System.Boolean]
        $RequireValidSignature,

        [Parameter()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String]
        $Thumbprint,

        [Parameter()]
        [System.String]
        $ServerCertificateValidationCallback,

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

    Write-Verbose 'Entering Get-TargetResource in file DSC_xSoftwareInstallResource.psm1.'

    $CommonParameters = & { [CmdletBinding( SupportsShouldProcess )]param() $MyInvocation.MyCommand.Parameters.Keys }
    $PackageParameters = $MyInvocation.MyCommand.Parameters.Keys.Where({ $_ -notin $CommonParameters })
    
    $Package = [ordered]@{}
    $PackageParameters | ForEach-Object {
        
        $Package[$_] = (Get-Variable -Name $_ -ErrorAction SilentlyContinue).Value
        if ( $_ -eq 'Name' ) { $Package['ProductId'] = $null }

    }

    $Package.Ensure = 'Absent'

    $UninstallEntry = Get-UninstallEntry @PSBoundParameters -LatestVersions 1

    if ( $UninstallEntry ) {
        $Package.Ensure            = 'Present'
        $Package.Name              = $UninstallEntry.Name
        $Package.ProductId         = $UninstallEntry.ProductId.ToString('B')
        $Package.Publisher         = $UninstallEntry.Publisher
        $Package.Version           = $UninstallEntry.Version.ToString()
        $Package.VersionComparison = 'EqualTo'
    }

    # if no install string provided, we're going to assume a bare command for .EXE and default .MSI command
    if ( [string]::IsNullOrEmpty( $InstallCommand ) ) {

        if ( $Type -eq 'MSI' ) { 

            $Package.InstallCommand = 'msiexec.exe /I "{0}" /QN /norestart'

            if ( $LogPath ) {

                $Package.InstallCommand += ' /log "{1}"'

            }

        } elseif ( $Type -eq 'EXE' ) {
            
            $Package.InstallCommand = '"{0}"'

        }

    }

    # if no uninstall string is provided we'll use the value from the uninstall entry
    if ( [string]::IsNullOrEmpty( $UninstallCommand ) ) {

        if ( $Type -eq 'MSI' ) { 

            $Package.UninstallCommand = 'msiexec.exe /X{2} /QN /norestart'

            if ( $LogPath ) {

                $Package.UninstallCommand += ' /log "{1}"'

            }

        } elseif ( $Type -eq 'EXE' -and $UninstallEntry ) {
            
            if ( $UninstallEntry.QuietUninstallString ) {

                $Package.UninstallCommand = $UninstallEntry.QuietUninstallString

            } elseif ( $UninstallEntry.UninstallString ) {
                
                $Package.UninstallCommand = $UninstallEntry.UninstallString
                
            }

        }

    }

    return $Package

}


function Test-TargetResource {

    [CmdletBinding( SupportsShouldProcess = $true )]
    param(

        [Parameter()]
        [ValidateSet( 'Present', 'Absent' )]
        [System.String]
        $Ensure = 'Present',

        [Parameter( Mandatory = $true )]
        [ValidateSet( 'MSI', 'EXE' )]
        [System.String]
        $Type,

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [System.String]
        $Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [System.String]
        $Publisher,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Version,

        [Parameter()]
        [ValidateSet( 'Any', 'LessThan', 'LessThanOrEqualTo', 'EqualTo', 'GreaterThanOrEqualTo', 'GreaterThan' )]
        [System.String]
        $VersionComparison = 'EqualTo',

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri,

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
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UninstallCommand,

        # Return codes 1641 and 3010 indicate success when a restart is requested per installation
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.UInt32[]]
        $UninstallReturnCode = @( 0, 3010 ),

        [Parameter()]
        [System.Boolean]
        $UninstallRequiresInstaller = $false,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [System.Boolean]
        $UseDefaultCredential = $false,

        [Parameter()]
        [System.String]
        $Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $ProxyCredential,

        [Parameter()]
        [System.Boolean]
        $ProxyUseDefaultCredential,

        [Parameter()]
        [System.String]
        $LogPath,

        [Parameter()]
        [System.String]
        $Hash,

        [Parameter()]
        [ValidateSet( 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160' )]
        [System.String]
        $Algorithm,

        [Parameter()]
        [System.Boolean]
        $RequireValidSignature,

        [Parameter()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String]
        $Thumbprint,

        [Parameter()]
        [System.String]
        $ServerCertificateValidationCallback,

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

    Write-Verbose 'Entering Test-TargetResource in file DSC_xSoftwareInstallResource.psm1.'

    $Package = Get-TargetResource @PSBoundParameters

    Write-Verbose ( 'Software status: {0}' -f $Package.Ensure )

    return $Ensure -eq $Package.Ensure

}


function Set-TargetResource {

    [CmdletBinding( SupportsShouldProcess = $true )]
    param(

        [Parameter()]
        [ValidateSet( 'Present', 'Absent' )]
        [System.String]
        $Ensure = 'Present',

        [Parameter( Mandatory = $true )]
        [ValidateSet( 'MSI', 'EXE' )]
        [System.String]
        $Type,

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [System.String]
        $Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [System.String]
        $Publisher,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Version,

        [Parameter()]
        [ValidateSet( 'Any', 'LessThan', 'LessThanOrEqualTo', 'EqualTo', 'GreaterThanOrEqualTo', 'GreaterThan' )]
        [System.String]
        $VersionComparison = 'EqualTo',

        [Parameter( Mandatory = $true )]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri,

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
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UninstallCommand,

        # Return codes 1641 and 3010 indicate success when a restart is requested per installation
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.UInt32[]]
        $UninstallReturnCode = @( 0, 3010 ),

        [Parameter()]
        [System.Boolean]
        $UninstallRequiresInstaller = $false,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [System.Boolean]
        $UseDefaultCredential = $false,

        [Parameter()]
        [System.String]
        $Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $ProxyCredential,

        [Parameter()]
        [System.Boolean]
        $ProxyUseDefaultCredential,

        [Parameter()]
        [System.String]
        $LogPath,

        [Parameter()]
        [System.String]
        $Hash,

        [Parameter()]
        [ValidateSet( 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160' )]
        [System.String]
        $Algorithm,

        [Parameter()]
        [System.Boolean]
        $RequireValidSignature,

        [Parameter()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String]
        $Thumbprint,

        [Parameter()]
        [System.String]
        $ServerCertificateValidationCallback,

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

    Write-Verbose 'Entering Set-TargetResource in file DSC_xSoftwareInstallResource.psm1.'

    $ErrorActionPreference = 'Stop'

    $Package = Get-TargetResource @PSBoundParameters

    if ( $Ensure -eq $Package.Ensure ) {
        
        Write-Verbose 'Package in desired state.'
        return
    
    }

    Write-Verbose 'Package configuration starting.'

    $InstallerUri = $Uri -as [uri]
    $Installer = $null

    $CacheFolder = Get-CacheFolder $Name

    if ( $Ensure -eq 'Present' -or $UninstallRequiresInstaller ) {

        $Installer = switch -Regex ( $InstallerUri.Scheme ) {
            
            '^(ht|f)tps?$' {
            
                Invoke-WebFileDownload @PSBoundParameters -OutputFolder $CacheFolder | Convert-Path
            
            }

            '^file$' {

                if ( $InstallerUri.IsUnc ) {

                    Invoke-FileCopy @PSBoundParameters -OutputFolder $CacheFolder | Convert-Path

                } else {

                    Get-Item -LiteralPath $InstallerUri.AbsolutePath -ErrorAction Stop | Convert-Path

                }

            }

            default {

                throw ( 'Unsupported URI scheme: {0}' -f $_ )

            }

        }

        if ( -not $Installer ) {

            Write-Error 'Installer was not found.' -ErrorAction Stop

        }

        if ( $Hash ) {

            Assert-FileHashValid -Path $Installer @PSBoundParameters

        } else {

            Write-Warning 'File hash was not verified!'

        }

        if ( $RequireValidSignature -or $Subject -or $Thumbprint ) {

            Assert-FileSignatureValid -Path $Installer @PSBoundParameters

        } else {

            Write-Warning 'File signature was not verified!'
            
        }

    }

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

    # are we installing or uninstalling?
    $CommandLine = $Package.InstallCommand, $Package.UninstallCommand | Select-Object -Index ( $Ensure -eq 'Absent' )
    $ValidReturnCodes = $ReturnCode, $UninstallReturnCode | Select-Object -Index ( $Ensure -eq 'Absent' )
    $CommandTypeVerb = 'install', 'uninstall' | Select-Object -Index ( $Ensure -eq 'Absent' )

    # if the command line is empty throw an error, user must supply a command line
    if ( [string]::IsNullOrEmpty( $CommandLine ) ) {

        Write-Error ( 'No {0} command supplied, and command was not able to be automatically generated.' -f $CommandTypeVerb ) -ErrorAction Stop

    }

    # escape any curly brace that is not explicitly '{0}', '{1}', etc..
    $CommandLine = $CommandLine -replace '{(?!\d})', '{{' -replace '(?<!{\d)}', '}}'

    # interpolate the Installer, Log Path, and Product ID in the command
    $CommandLine = $CommandLine -f $Installer, $LogPath, $Package.ProductId

    if ( $PSCmdlet.ShouldProcess( ( 'Run command line: {0}' -f $CommandLine ), $null, $null ) ) {
            
        #$ExitCode = Invoke-CommandLine -CommandLine $CommandLine

        $StartProcessSplat = ConvertFrom-CommandLine $CommandLine
        if ( $RunAsCredential ) {
            $StartProcessSplat.Credential = $RunAsCredential
        }

        $Process = Start-Process @StartProcessSplat -PassThru

        $InstallTimeout = $null
        
        $WaitProcessSplat = @{
            ErrorAction = 'SilentlyContinue'
            ErrorVariable = 'InstallTimeout'
        }

        if ( $TimeoutSeconds ) {
            $WaitProcessSplat = @{ Timeout = $TimeoutSeconds }
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

    if ( -not $UninstallRequiresInstaller ) {

        Remove-CacheFolder $Name
        
    }

}

