<#
 ==============================================================================================
 THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
 FITNESS FOR A PARTICULAR PURPOSE.

 This sample is not supported under any Microsoft standard support program or service. 
 The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
 implied warranties including, without limitation, any implied warranties of merchantability
 or of fitness for a particular purpose. The entire risk arising out of the use or performance
 of the sample and documentation remains with you. In no event shall Microsoft, its authors,
 or anyone else involved in the creation, production, or delivery of the script be liable for 
 any damages whatsoever (including, without limitation, damages for loss of business profits, 
 business interruption, loss of business information, or other pecuniary loss) arising out of 
 the use of or inability to use the sample or documentation, even if Microsoft has been advised 
 of the possibility of such damages.
 ==============================================================================================

 ----------------------------------------------------------------------------------------------
 Note that there is absolutely nothing to configure here. All Configuration is done in an
 XML File that you specify when calling the Script via the "-ConfigFile" Parameter.
 ----------------------------------------------------------------------------------------------
 #>

<#
    .SYNOPSIS
    Setup ADCS out of XML-based configuration files in a two-pass approach. Pass 1 installs the 
    binaries and creates the cert request while pass 2 installs the final cert and is doing all
    the configurations. Typically, a reboot should be done between pass 1 and pass 2 to refresh
    the system's Kerberos token.
    Except: when installing a root CA, pass 1 and pass 2 are running seamlesss without reboot.
    The Script supports two parameter sets:
    ParameterSet "INSTALL"
        covers ADCS installation
    ParameterSet "VIEW"
        show/print chosen setup configuration 

    
    .PARAMETER ConfigFile
    Specify the Customer Configuration file here. It may either be a relative or an absolute path.
    if setup is running pass 2, the ConfigFile entered in pass 1 has been written into registry
    and will be used as default. Only be used when entered together with "OverwriteConfigInRegistry"
    switch, ConfigFile parameter will be used in pass 2. Otherwise ConfigFile parameter will be 
    ignored in pass 2.
    If no ConfigFile will be entered on the command line, a file selection dialogbox will open to
    select the config file.

    .PARAMETER Commit
    Add this Parameter to make the Script actually do anything. if missing, the configuration based on
    the used ConfigFile will be written to output window to get verified before application.
    Note: commit will be automatically $true when in pass 2 except when changing the parameterset
          to "View"

    .PARAMETER OverwriteConfigInRegistry
    Has only effect if running pass 2. ignores registry setting for ConfigFile and uses that one in
    the command parameter instead.
    (this parameter should be used with care as it allowes to mix different ConfigFiles)

    .PARAMETER CleanUp
    this will clean up the registry from temporary setup status entries. Can be used either in 
    pass 2 (together with the "commit" switch) to automaticall remove temporary setup status entries 
    after sucessful installation or in any pass without "commit" switch to remove fractals from earlier
    setups.

    .PARAMETER ViewConfig
    allows to any time reviewing the configuration. ViewConfig will not check for any installation 
    prerequirements and cannot be used with any of the other switches above.

    .PARAMETER Help
    display help.

   .Notes
    AUTHOR: Andreas Luy, MSFT; andreas.luy@microsoft.com
    last change 09.01.2020

 General To-Dos:
 - bring everything into a message window instead of command window
#>


[CmdletBinding(DefaultParameterSetName="Install")]
Param (
    [Parameter(Mandatory=$false,
        ParameterSetName="Install")]
    [Parameter(Mandatory=$false,
        ParameterSetName="View")]
    [String]$ConfigFile,

    [Parameter(Mandatory=$false,
        ParameterSetName="Install")]
    [Switch]$Commit,
    [Parameter(Mandatory=$false,
        ParameterSetName="Install")]
    [Switch]$OverwriteConfigInRegistry=$false,
    [Parameter(Mandatory=$false,
        ParameterSetName="Install")]
    [Switch]$CleanUp,

    [Parameter(Mandatory=$false,
        ParameterSetName="View")]
    [Switch]$ViewConfig,

    [Parameter(Mandatory=$false,
        ParameterSetName="Install")]
    [Parameter(Mandatory=$false,
        ParameterSetName="View")]
    [Switch]$Help


)


If ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    exit
}


#
#region necessary pre-reqs

$BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
# loading modules needed
Import-Module `
    -Name $Script:BaseDirectory\psmod\SW4XMLTools\SW4XMLTools.psm1 `
    -ErrorAction Stop

# loading .net classes needed
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

# loading all Libary Scripts we depend on
Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
    Try {
        Write-Verbose -Message "Loading $($_.FullName)"
        . ($_.FullName)
    }
    Catch {
        Write-Error -Message "Error loading $($_.FullName)"
        Exit
    }
}

#$ViewConfig = $true

$Global:SetupStatus =""
$global:ShowStopper = $False
$Now = $((Get-Date).ToString($(Get-Culture).DateTimeFormat.ShortDatePattern))

#region do you accept our EULA?

if(!(Display-Eula)){
    
    write-line "EULA has not been accepted - exiting!" "Warning"
    exit
}
#endregion

#region Prepare output window
Clear-Host
<#
$console = $host.UI.RawUI
$size = $console.WindowSize
$size.Width = 96
$size.Height = 60
$console.WindowSize = $size
$bufferSize = $console.BufferSize
$bufferSize.width = 96
$bufferSize.height = 1440
$console.BufferSize = $bufferSize
#>

#endregion

if(!$ViewConfig){
    # determine  ADCS installation status
    # can have several stati: 
        # "Blank", aka: pass 1
        # "InProgress", aka: pass 2;
        # "AlreadyInstalled", aka: why you are calling this program?
    $Global:SetupStatus = Check-SetupStatus 
    $Global:User = [Security.Principal.WindowsIdentity]::GetCurrent()
    #endregion
}

#checking wether "CleanUp" has been called after ADCS installation
if($CleanUp -and ($Global:SetupStatus -eq "AlreadyInstalled")){
    Remove-OaAdcsRegKeys
    write-line "Registry has been cleaned up - exiting!" "Warning"
    exit
}

#region define hard break criterias
# ADCS already installed ?
if($Global:SetupStatus -eq "AlreadyInstalled"){
    Break-MessageBox "ADCS is already installed!`r`nAborting setup!"
}

# config file entered ?
if((($Global:SetupStatus -eq "Blank") -or $ViewConfig) -and (!($ConfigFile))){
    $ConfigFile=Select-ConfigFile
    if(!$ConfigFile){
        Break-MessageBox "No config file entered`r`nAborting setup!"
    }
}

# prereqs met for pass 2 ?
if($Global:SetupStatus -eq "InProgress"){
    # has OverwriteConfigInRegistry been requested?
    if(!$OverwriteConfigInRegistry){
        # do we have the same user as in pass 1?
        if(!(Get-ItemProperty -Path $RegistryRoot -Name OaadcsInstallUser -ErrorAction SilentlyContinue)){
            Break-MessageBox "Registry information missing from previous script run: ""OaadcsInstallUser""!`r`nInvestigate root cause of missing registry key, remove current installation and restart the setup`r`nAborting setup!"
        }elseif(($Global:User).Name -ne (Get-ItemPropertyValue -Path $RegistryRoot -Name OaadcsInstallUser -ErrorAction SilentlyContinue)){
            Break-MessageBox ("Setup pass 1 was done with different user account: $(Get-ItemPropertyValue -Path $RegistryRoot -Name OaadcsInstallUser -ErrorAction SilentlyContinue)`r`nPlease use same user account to continue setup`r`nAborting setup!")
        }
        if((!(Get-ItemProperty -Path $RegistryRoot -Name OaadcsConfigFileLocation -ErrorAction SilentlyContinue))){
            Break-MessageBox "No config file provided and registry information missing from setup pass 1: ""OaadcsConfigFileLocation""!`r`nAborting setup!"
        }else{
            $ConfigFile= Get-ItemPropertyValue -Path $RegistryRoot -Name OaadcsConfigFileLocation
        }
    }elseif(!$ConfigFile){
        $ConfigFile=Select-ConfigFile
        if(!$ConfigFile){
            Break-MessageBox "No config file entered`r`nAborting setup!"
        }
    }
    # has CleanUp been requested? either from command line or from registry during pass 1
    $CleanUp=($CleanUp -or (if((Get-ItemProperty -Path $RegistryRoot -Name OaadcsCleanUp -ErrorAction SilentlyContinue) -eq 1){$true}else{$false}))

    # commit is automatically true in pass 2
    $commit=$True
}

# checking if config file exists ?
if(!(Test-Path $ConfigFile)){
    Break-MessageBox ("Config file cannot be found! - Aborting`r`n--> "+$ConfigFile)
    exit
}

#endregion

# ------------------------------------------------------
# start main
# ------------------------------------------------------
Write-OAHeading

if(($Global:SetupStatus -eq "Blank") -or $ViewConfig) {
    # Checking if the ConfigFile Argument was specified absolute or relative
    If (!([System.IO.Path]::IsPathRooted($ConfigFile))) {
        # path is somehow relative
        # now checking if Argument is a single file name or a relative path
        if ($ConfigFile.ToCharArray() -contains "\") {
            # path is relative to base directory
            $ConfigFile = "$Script:BaseDirectory\$ConfigFile"
        }else {
            # no path specified - only file name
            # Specifying the Root Folder for this and subsequent Config Files
            $ConfigFile= "$Script:BaseDirectory\conf\$ConfigFile"
        }
    }
}
if($Global:SetupStatus -eq "Blank"){
    Write-Header -Text "----- Running CA setup ---- pass 1 ..."

}elseif($Global:SetupStatus -eq "InProgress"){
    Write-Header -Text "----- Running CA setup ---- pass 2 ..."
}
Write-Line " "
Write-Line " "
Write-Line " "

# Reading Configuration from XML File
#
$Config = Get-XmlConfig "$ConfigFile"


if(!$ViewConfig){
    # Critical Checks that force us to Stop Execution
    #
    Check-AccountPreReqs
    if($Global:SetupStatus -eq "Blank"){
        Check-OSPreReqs
        Check-CaObjectExist
        Check-KSPPreReqs
    }
}
Write-Line " "

# Automagically setting the maximum validity period of the issued certificates
# if missing in ConfigFile
If (-not $Config.Config.CA.Settings.ValidityPeriodUnits) {
    # Simply set to 1/2 of the CA Certificate Validity Period
    $Config.Config.CA.Settings.ValidityPeriodUnits = [math]::Floor($Config.Config.CA.Certificate.ValidityPeriodUnits/2)
}

If (-not $Config.Config.CA.Settings.ValidityPeriod) {
    # Use the same Value as for the CA Certificate
    $Config.Config.CA.Settings.ValidityPeriod = $($Config.Config.CA.Certificate.ValidityPeriod)
}
# if value does not exist assign "Default" 
if(!($Config.Config.CA.CertificateProfile)){$Config.Config.CA.CertificateProfile="Default"}


#region check database & log file configuration for consitency
if($Global:SetupStatus -eq "Blank"){
    If (-not $Config.Config.CA.DatabaseDirectory) {
        $Config.Config.CA.DatabaseDirectory = "$($env:systemroot)\System32\CertLog"
    }
    If(!(test-path -IsValid $Config.Config.CA.DatabaseDirectory)){
        $global:ShowStopper = $True
        Write-Line "Database directory format is invalid!" "Error"
    }

    If (-not $Config.Config.CA.LogDirectory) {
        $Config.Config.CA.LogDirectory = $Config.Config.CA.DatabaseDirectory
    }
    If(!(test-path -IsValid $Config.Config.CA.LogDirectory)){
        $global:ShowStopper = $True
        Write-Line "Log File directory format is invalid!" "Error"
    }

    if((Get-PSDrive (($Config.Config.CA.DatabaseDirectory.Split(":"))[0]) -ErrorAction SilentlyContinue) -eq $null){
        $global:ShowStopper = $True
        Write-Line "Database directory drive does not exist!" "Error"
    }

    if((Get-PSDrive (($Config.Config.CA.LogDirectory.Split(":"))[0]) -ErrorAction SilentlyContinue) -eq $null){
        $global:ShowStopper = $True
        Write-Line "Log File directory drive does not exist!" "Error"
    }
}

# Automagically building a CApolicy.inf
if(($Global:SetupStatus -eq "Blank") -or $ViewConfig){
    $CaPolicy = Get-CaPolicy -Config $Config
}
#endregion


#
# Starting the CA Setup Routine, if -Commit is $True
# otherwise (default), print the current Configuration
#

If ($Commit) {
    #
    # Installing the Certification Authority if no showstopper...
    #

    If ($global:ShowStopper) {
        Break-MessageBox "One or more errors found - setup stopped!"
        Write-Line "One or more errors found - setup stopped!" "Error"
        exit
    }


    $TranscriptFile = "$($env:SystemDrive)\CaSetup_$($Config.Config.CA.Name.Replace(" ","_"))_$(Get-Date -format yyyyMMdd_HHmmss).txt"
    Trap {Continue} Start-Transcript -path $TranscriptFile

    # At this time, there should be no Configuration yet
    # If so, we make one now
    if($Global:SetupStatus -eq "Blank"){
        Configure-Prereqs
        Install-ADCSSvc
    }

    # the following only applies to subordinated CAs that are waiting for cert request to be answered
    If ((Parse-SetupStatus) -ne "0") {
        Install-CaCert
    }
    if ((Parse-SetupStatus) -eq "0"){
        # means the cert has been installed
        Configure-CaSrv

        # Restarting Certification Authority Service and wait until it is up again
        Stop-Service CertSvc 

        Write-Line "Waiting 30 Seconds for KSPs to close their Handles..." "Warning"
        Start-Sleep -Second 30

        Start-Service CertSvc 

        While (-not (Check-AdcsServiceAvailability -eq $True)) {

            Write-Line "Waiting for the ICertAdmin2 Interface to become available..." "Warning"

            # We should not poll too often as every time the Query fails, we will
            # have an ugly DCOM Error Message 10016 in the System Event Log
            Start-Sleep 10

        }
		Start-Sleep -Second 30

        # Deleting the old CRLs
        Get-ChildItem $CertEnrollFolder "$($Config.Config.CA.Name)*.crl" | Remove-Item

        # Issuing a new CRL - might fail due to missing object, but will create the local file
        Write-Line "Issuing first CRL with new Configuration. This might fail the first time."
        Run-MonitoredCommand -Command "certutil -CRL"

        # A routine to ensure we have the non-Default LDAP Object in place
        # Only when this is an Enterprise CA, and if it uses LDAP CDPs
        If ($Config.Config.CA.Type -eq "EnterpriseSubordinateCA") {
            $Config.Config.CA.Settings.Extensions.CDP | ForEach-Object {

                If ($_.Protocol -eq "ldap") {

                    If ($_.URL -notmatch $DefaultLdapCdp) {

                        $LdapCDPContainer=if((($_.URL).split(","))[1] -eq "CN=CDP"){""}else{(((($_.URL).split(","))[1]).split("="))[1]}

                        Write-Line "Creating non-Standard LDAP CDP Object Container if necessary"

	                    # Creating the object by force
	                    Get-ChildItem $CertEnrollFolder "$($Config.Config.CA.Name)*.crl" | Foreach-Object {
							Run-MonitoredCommand -Command "certutil -f -dspublish ""$($_.FullName)"" ""$LdapCDPContainer""" 
	                    }
                    }
                }
                if ($_.Protocol -eq "file") {
                    # checking for UNC path
                    If (!(($_.URL).StartsWith("\\"))) {
                        # no UNC path so create folders if it does not exist
                        if(!(Test-Path (($_.URL).TrimEnd(($_.URL).Split("\")[($_.URL).Split("\").count-1])))){
                            Write-Line ("Creating non-Standard CDP file path "+($_.URL).TrimEnd(($_.URL).Split("\")[($_.URL).Split("\").count-1]))
                            mkdir (($_.URL).TrimEnd(($_.URL).Split("\")[($_.URL).Split("\").count-1]))
                        }
                    }
                }
            }
        }

	    # Issuing a new CRL - should work now if System already has been rebooted
	    Run-MonitoredCommand -Command "certutil -CRL"

        #
        # Finished! Printing out next manual Steps for the User
        #

        Write-Header -Text "Your To-Dos after the Installation:"

        $HttpCdp = $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "http"} | Select URL
        $FtpCdp = $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "ftp"} | Select URL
        $LdapCdp = $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "ldap"} | Select URL
        $FileCdp = $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "file"} | Select URL

        $HttpAia = $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "http"} | Select URL
        $LdapAia = $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "ldap"} | Select URL
        $OcspAia = $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "ocsp"} | Select URL

        If ($Config.Config.CA.Type -eq "StandaloneRootCA") {

            Write-Line "- Upload CA Certificate to trusted Root CAs in AD with certutil -f -dspublish <Filename> RootCA" "Warning"
            If ($LdapCdp) {
                Write-Line "- Upload Revocation List to AD with certutil -f -dspublish <Filename>" "Warning"
            }

        } ElseIf ($Config.Config.CA.Type -eq "StandaloneSubordinateCA") {
            Write-Line "- Upload CA Certificate to AIA in AD with certutil -f -dspublish <Filename> SubCA" "Warning"
            If ($LdapCdp) {
                Write-Line "- Upload Revocation List to AD with certutil -f -dspublish <Filename>" "Warning"
            }
        } Else {
            If ($LdapCdp) {
                If ($LdapCdp -notmatch $DefaultLdapCdp) {
                    $Config.Config.CA.DsConfigDn = (Get-ItemProperty -Path "$RegistryRoot\$($Config.Config.CA.Name)" -Name DsConfigDn).DsConfigDn
                    $DefaultLdapCdp = $DefaultLdapCdp.Replace("%2",$($env:computername))
                    $DefaultLdapCdp = $DefaultLdapCdp.Replace("%6",$Config.Config.CA.DsConfigDn)
                    $DefaultLdapCdp = $DefaultLdapCdp.Replace("%10","")
                    Write-Line "- Delete the Default LDAP CDP Object under $DefaultLdapCdp" "Warning"
                }
            }
        }

        If ($HttpAia) {
            Write-Line "- Upload CA Certificate to your Web Server(s)"  "Warning"
        }

        If ($HttpCdp) {
            If (-not ($FileCdp -match "\\")) {
                Write-Line "- Upload Revocation List to your Web Server(s)" "Warning"
            }
        }

        If ($FtpCdp) {
            If (-not ($FileCdp -match "\\")) {
                Write-Line "- Upload Revocation List to your FTP Server(s)" "Warning"
            }
        }

        If ($Config.Config.CA.Settings.AuditFilter -ne 0) {
            Write-Line "- Ensure that Auditing for CA Object Access is enabled via Group Policy" "Warning"
        }

        # checking if "CleanUp" has been called in pass 2
        if($CleanUp){
            Remove-OaAdcsRegKeys
            write-line "Registry has been cleaned up ..." "Warning"
        }

        # Finished!
        Trap {Continue} Stop-Transcript 
        If (Test-Path $TranscriptFile) {
            [string]::join("`r`n",(Get-content $TranscriptFile)) | Out-File $TranscriptFile
        }
    }

} Elseif($ViewConfig){
    Write-Config2Window
}else{
    Write-Config
}