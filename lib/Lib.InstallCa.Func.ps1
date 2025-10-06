# ==============================================================================================
# THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
# ==============================================================================================

# andreas.luy@microsoft.com
# 04.11.2019

$CertEnrollFolder = "$($env:systemroot)\System32\CertSrv\CertEnroll"
$DefaultLdapCdp = "ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10"
$CaPolFile = "$env:SystemRoot\capolicy.inf"
#$CertFile = ".\certnew.cer"
$RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"


Function Check-AdcsServiceAvailability
{

    # Checks the availability of the ICertAdmin2 interface on the local System
    # Returns $True if the Interface is available and $False if not
    # shamelessly taken from https://gallery.technet.microsoft.com/scriptcenter/Certificate-Authority-0c39cb4a

    # First we try to get the ICertAdmin2 Interface
    Try {
        $CertConfig = New-Object -ComObject CertificateAuthority.Config
        $Config = $CertConfig.GetConfig(0)
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin.1

    } Catch  {
        Return $False
    }

    # Then we try to do a Query over the Interface
    Try {
        $retn = $CertAdmin.GetCAProperty($Config,0x6,0,4,0)
        Return $True
    } Catch {
        Return $False
    }

}

function Remove-OaAdcsRegKeys
{
    if(Get-ItemProperty -Path $RegistryRoot -Name OaadcsConfigFileLocation -ErrorAction SilentlyContinue){
        Write-Line "Removing: $RegistryRoot\OaadcsConfigFileLocation"
        Remove-ItemProperty -path $RegistryRoot -name OaadcsConfigFileLocation
    }
    if(Get-ItemProperty -Path $RegistryRoot -Name OaadcsInstallUser -ErrorAction SilentlyContinue){
        Write-Line "Removing: $RegistryRoot\OaadcsInstallUser"
        Remove-ItemProperty -path $RegistryRoot -name OaadcsInstallUser
    }
    if(Get-ItemProperty -Path $RegistryRoot -Name OaadcsCleanUp -ErrorAction SilentlyContinue){
        Write-Line "Removing: $RegistryRoot\OaadcsCleanUp"
        Remove-ItemProperty -path $RegistryRoot -name OaadcsCleanUp
    }
}

Function Test-RegistryValue
{

    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]$Value
    )

    If((Get-ItemProperty -Path $Path -Name $Value -ErrorAction SilentlyContinue)){
        Return $True
    }else{
        Return $False
    }
}

Function Parse-SetupStatus
{
    # Checking for the *presence* of SETUP_REQUEST_FLAG -- 8
    # If this is present the CA is waiting for the Certificate Request to be signed
    $SetupStatus = (Get-ItemProperty -Path "$RegistryRoot\$((Get-ItemPropertyValue -Path "$RegistryRoot" -Name Active))" -Name SetupStatus -ErrorAction SilentlyContinue).SetupStatus

    # When we use -bAnd and the bit is set we will get the decimal value for this bit returned.
    # If the bit is not set we will get 0 returned
    [string]$ret =([convert]::ToString($SetupStatus,2) -band 8)
    return $ret
}

Function Build-Argumentlist
{
        If(!(Test-Path $Config.Config.CA.DatabaseDirectory)) {
            Write-Line "Creating Directory $($Config.Config.CA.DatabaseDirectory)"
            mkdir $Config.Config.CA.DatabaseDirectory | Out-Null
        }

        If(!(Test-Path $Config.Config.CA.LogDirectory)) {
            Write-Line "Creating Directory $($Config.Config.CA.LogDirectory)"
            mkdir $Config.Config.CA.LogDirectory | Out-Null
        }
		
        # Dynamically filling the Arguments is called "Splatting"
        if (($Config.Config.CA.Crypto.KeyAlgorithm).ToLower() -eq "ecc") {
            $Config.Config.CA.Crypto.KeyAlgorithm = "ECDSA_P$($Config.Config.CA.Crypto.KeyLength)"
        }
        $Arguments = @{
    
            CAType = $Config.Config.CA.Type
            CACommonName = $Config.Config.CA.Name
            KeyLength = $Config.Config.CA.Crypto.KeyLength
            DatabaseDirectory = $Config.Config.CA.DatabaseDirectory
            LogDirectory = $Config.Config.CA.LogDirectory
            HashAlgorithm = $Config.Config.CA.Crypto.SignatureHashAlgorithm
            CryptoProviderName = "$($Config.Config.CA.Crypto.KeyAlgorithm)#$($Config.Config.CA.Crypto.KspName)"
            OverwriteExistingKey = $True
            OverwriteExistingDatabase = $True
            Force = $True
        }

        If ($Config.Config.CA.DistinguishedNameSuffix) {
            $Arguments.Add("CADistinguishedNameSuffix", $Config.Config.CA.DistinguishedNameSuffix)
        }

        If ($Config.Config.CA.AllowAdministratorInteraction -eq "True") {
            $Arguments.Add("AllowAdministratorInteraction", $True)
        }

        Switch ($Config.Config.CA.Type) {

            "StandaloneRootCA" {
                $Arguments.Add("ValidityPeriod", $Config.Config.CA.Certificate.ValidityPeriod)
                $Arguments.Add("ValidityPeriodUnits", $Config.Config.CA.Certificate.ValidityPeriodUnits)
                }
            "StandaloneSubordinateCA" {
                $CaCsrFile = "$($env:SystemDrive)\csr_$($($Config.Config.CA.Name).Replace(" ","_")).req" 
                $Arguments.Add("OutputCertRequestFile", $CaCsrFile)
                }
            "EnterpriseSubordinateCA" {
                $CaCsrFile = "$($env:SystemDrive)\csr_$($($Config.Config.CA.Name).Replace(" ","_")).req" 
                $Arguments.Add("OutputCertRequestFile", $CaCsrFile)
            }

        }
        return $Arguments
}

Function Install-ADCSSvc
{
    $ret = $true
    # Installing the Windows Feature only if required
    If ((Get-WindowsFeature Adcs-Cert-Authority).Installed -eq $False) {

        Write-Header -Text "Installing the Certification Authority Role"

        try {
            Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools -ErrorAction Stop
        } catch {
            Write-Host "ADCS installation failed with error:`r`n$($_.Exception.Message)`r`n`r`nAborting ..."
            $ret = $false
        }
    }

    # Write the CaPolicy to the Windows Directory
    $CaPolicy | Out-File $CaPolFile -Encoding ascii -Force

    $InstallArgs = Build-Argumentlist

    Write-Header -Text "Configuring the Certification Authority Role"

    try {
        #Install-AdcsCertificationAuthority @InstallArgs -WhatIf
        Install-AdcsCertificationAuthority @InstallArgs -ErrorAction Stop
    } catch {
        Write-Host "ADCS installation failed with error:`r`n$($_.Exception.Message)`r`n`r`nAborting ..."
        foreach ($arg in $InstallArgs) {
            Write-Host $Arg
        }
        $ret = $false
        #$msgBoxInput=[System.Windows.MessageBox]::Show("Stop now?","Waiting...","YesNo","Warning","No")
    }

    If (($Config.Config.CA.Type -eq "EnterpriseSubordinateCA") -or ($Config.Config.CA.Type -eq "StandaloneSubordinateCA")) {

        #before stopping setup, ensure that we have necessary status information written into registry
        Write-Line " "
        Write-Line "Writing registry information for pass 2..."
        Write-Line " "
        New-ItemProperty $RegistryRoot -Name OaadcsConfigFileLocation -PropertyType String -Value $ConfigFile -Force|Out-Null
        New-ItemProperty $RegistryRoot -Name OaadcsInstallUser -PropertyType String -Value ($Global:User).Name -Force|Out-Null
        if($CleanUp){
            New-ItemProperty $RegistryRoot -Name OaadcsCleanUp -PropertyType DWord -Value 1 -Force|Out-Null
        }

        # Rebooting the Machine to update Group Membership of Cert Publishers Group
        Write-Line "The CA Service has been installed." "Warning"
        Write-Line "You must now submit the Certificate Signing Request (to be found under $($InstallArgs.OutputCertRequestFile)) to a Root CA." "Warning"
        Write-Line "Once you have your CA Certificate, name it $CertFile, place it in the same Directory as this script." "Warning"
        Write-Line "Then, run the Script again to finish the Installation." "Warning"

        If ($Config.Config.CA.Type -eq "EnterpriseSubordinateCA") {
            $msgBoxInput=[System.Windows.MessageBox]::Show("Server needs to reboot to update group memberships. Do you want to reboot now?","Reboot Waiting...","YesNo","Warning","No")
            switch  ($msgBoxInput) {
                "Yes" {                
                    Restart-Computer -Force
                    }
                "No" {
                    Write-Line "Setup stopped." "Warning"
                    Write-Line "Don't forget to manually reboot the system before continuing!" "Warning"
                    exit
                }
            }
        }else{
            Write-Line "Setup stopped." "Warning"
            exit
        }
    }
}

Function Install-CaCert
{
    Write-Header -Text "Installing the CA Certificate"
    $CertFile = Select-NewCertFile
    # Ensuring that new CA Certificate File is in place
    If (Test-Path $CertFile) {
        If ($Config.Config.CA.Type -eq "EnterpriseSubordinateCA"){
	        # Updating Machine Policy to ensure Root CA Cert was downloaded from AD
            # This will both trigger Propagation via Group Policy and via AutoEnrollment
            Run-MonitoredCommand -Command "certutil -pulse"
            Start-Sleep -Second 15
        }
        Write-Line "Verifying that chain and revocation will work for $($CertFile)."
        Write-Line "running certutil -verify $($CertFile)"
        Write-Line "This might take a moment..."
        $result= certutil -verify $CertFile
        $ErrorStat=($result|findstr "dwErrorStatus=")
        foreach ($line in $ErrorStat){
            if((($line.split(" ")[2]).split("=")[1]) -ne "0"){
                Write-Line "Verification of $($CertFile) failed with:"
                Write-Line $line "Error"
                Write-Line " "
                Write-Line "Review certificate verification in detail to identify the root cause!" "Warning"
                foreach ($line in $result){if($line){Write-Line ($line)}else{Write-Line " "}}
                Write-Line " "
                Write-Line "Verify root CA trust status and revocation!" "Warning"
                Write-Line "Rerun script again, when issues have been fixed." "Warning"
                Write-Line "Setup stopped." "Warning"
                exit
            }
        }
        Write-Line "certutil -verify $($CertFile) completed successfully" "Success"

        # check the result and abort if ist was not successful!

	    # Installing the CA Certificate
        Run-MonitoredCommand -Command "certutil -installcert ""$($CertFile)"""

        If ($LASTEXITCODE -ne 0) {
            Write-Line "An Error occurred while installing CA Certificate $($CertFile). Aborting Setup!" "Error"
            exit
        }
    } Else { 
        Write-Line "No CA certificate found in $($CertFile). Aborting Setup!" "Error"
        exit 
    }

}

Function Configure-CaSrv
{
    Write-Header -Text "Configuring the Registry"
    If (($Config.Config.CA.Type -eq "StandaloneRootCA") -or ($Config.Config.CA.Type -eq "StandaloneSubordinateCA")) {

        Run-MonitoredCommand -Command "certutil -setreg CA\DSConfigDN $($Config.Config.CA.DsConfigDn)"
    }

    # Applying Path Length Constraint
    If ($Config.Config.CA.Policy.PathLength) {
        Run-MonitoredCommand -Command "certutil -setreg Policy\CAPathLength $($Config.Config.CA.Policy.PathLength)"
    }
    
    # CRL Configuration
    Run-MonitoredCommand -Command "certutil -setreg CA\CRLPeriodUnits $($Config.Config.CA.Settings.CRL.PeriodUnits)"
    Run-MonitoredCommand -Command "certutil -setreg CA\CRLPeriod $($Config.Config.CA.Settings.CRL.Period)"
    Run-MonitoredCommand -Command "certutil -setreg CA\CRLOverlapUnits $($Config.Config.CA.Settings.CRL.OverlapUnits)"
    Run-MonitoredCommand -Command "certutil -setreg CA\CRLOverlapPeriod $($Config.Config.CA.Settings.CRL.OverlapPeriod)"

    # Delta CRL Configuration
    Run-MonitoredCommand -Command "certutil -setreg CA\CRLDeltaPeriodUnits $($Config.Config.CA.Settings.CRL.DeltaPeriodUnits)"
    Run-MonitoredCommand -Command "certutil -setreg CA\CRLDeltaPeriod $($Config.Config.CA.Settings.CRL.DeltaPeriod)"
    Run-MonitoredCommand -Command "certutil -setreg CA\CRLDeltaOverlapUnits $($Config.Config.CA.Settings.CRL.DeltaOverlapUnits )" 
    Run-MonitoredCommand -Command "certutil -setreg CA\CRLDeltaOverlapPeriod $($Config.Config.CA.Settings.CRL.DeltaOverlapPeriod)"
        
    # Validity Period
    Run-MonitoredCommand -Command "certutil -setreg CA\ValidityPeriodUnits $($Config.Config.CA.Settings.ValidityPeriodUnits)" 
    Run-MonitoredCommand -Command "certutil -setreg CA\ValidityPeriod $($Config.Config.CA.Settings.ValidityPeriod)"

    # Enabling Auditing at the CA Level
    Run-MonitoredCommand -Command "certutil -setreg CA\Auditfilter $($Config.Config.CA.Settings.AuditFilter)"

    # Enabling Auditing at the OS Level
    If ($Config.Config.CA.Settings.AuditFilter -gt 0) {
        Write-Line "Configuring local Audit Policy to enable Object Access Auditing for Certification Services"
        Run-MonitoredCommand -Command "auditpol /set /subcategory:""{0CCE9221-69AE-11D9-BED3-505054503030}"" /success:enable /failure:enable"
    }

    # If the EncryptionCsp has been specified, we make the setting in the Registry
    If ($Config.Config.CA.Crypto.EncryptionCspName) {
        Run-MonitoredCommand -Command "certutil -setreg CA\EncryptionCSP\Provider ""$($Config.Config.CA.Crypto.EncryptionCspName)"""
    }

    # Settings required to issue Certificates compliant to Common PKI requirements
    If (($Config.Config.CA.CertificateProfile).toLower() -eq "commonpki") {

        # Force UTF-8 Encoding of Subject Names
        Run-MonitoredCommand -Command "certutil -setreg CA\forceteletex +0x20"

        # make the Key Usage Extension Critical
        If (($Config.Config.CA.Type -eq "StandaloneRootCA") -or ($Config.Config.CA.Type -eq "StandaloneSubordinateCA")) {
            Write-Line "Configuring CA to enable critical KeyUsage extension"
            Run-MonitoredCommand -Command "certutil -setreg policy\EditFlags -EDITF_ADDOLDKEYUSAGE"
        }
    }elseif(($Config.Config.CA.CertificateProfile).toLower() -ne "microsoft-legacy") {
        # make the Key Usage Extension Critical
        If (($Config.Config.CA.Type -eq "StandaloneRootCA") -or ($Config.Config.CA.Type -eq "StandaloneSubordinateCA")) {
            Write-Line "Configuring CA to enable critical KeyUsage extension"
            Run-MonitoredCommand -Command "certutil -setreg policy\EditFlags -EDITF_ADDOLDKEYUSAGE"
        }
    }

    # Allow custom subject formats (necessary for e.g. eIDas compliance to include Organisation Identifier in Issued Certificates (OID 2.5.4.97))
    If ($Config.Config.CA.IncludeNonDefinedRDN -ne $null) {
        If ($Config.Config.CA.IncludeNonDefinedRDN.ToLower() -eq "true") {
            Write-Line "Configuring CA to enable non-defined RDN in request"
            Run-MonitoredCommand -Command "certutil -setreg policy\EditFlags +CRLF_REBUILD_MODIFIED_SUBJECT_ONLY"
        }
    }

    If ($Config.Config.CA.RemoveMSFTExtensions -ne $null) {
        If (($Config.Config.CA.RemoveMSFTExtensions).ToLower() -eq "true") {
            # Remove Microsoft specific Extensions from issued Certificates
            # Removing the CA version and previous hash extensions will have no ill-effect on normal CA operations.
            # They are used when restoring a CA, so that you can select the newest CA cert.
            # When doing so, the role installation code uses these extensions to collect an ordered 
            # list of all of the CA certs, so their thumbprints can be placed in the registry.
            # If these extensions are missing, the admin restoring the CA may need to manually add the thumbprints, or re-order them.
            # This means the admin will have to know which certs were used by the CA, and in what order they were installed.
            # The NotBefore and NotAfter fields may help with ordering.

            # szOID_CERTSRV_CA_VERSION (CA Version)
            Run-MonitoredCommand -Command "certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.21.1"

            # szOID_CERTSRV_PREVIOUS_CERT_HASH (Previous CA Certificate Hash)
            Run-MonitoredCommand -Command "certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.21.2"

            If ($Config.Config.CA.Type -eq "StandaloneRootCA") {

                # szOID_ENROLL_CERTTYPE_EXTENSION (v1 Template Name)
                Run-MonitoredCommand -Command "certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.20.2"
            }
        }
    }

    Write-Header -Text "Configuring CDP and AIA Extensions"

    # Clearing the existing CDP Configuration, leaving only the default local Path
    Get-CaCrlDistributionPoint | Where { !($_.Uri -match "\\") } | Foreach-Object {
        Write-Line "Removing CDP $($_.Uri)" "warning"
        Remove-CaCrlDistributionPoint $_.Uri -Force | Out-Null
    } 
    write-Line " "

    # Filling the specified CDP Paths in the desired order
    $Config.Config.CA.Settings.Extensions.CDP | ForEach-Object {

        Write-Line "Adding CDP $(Get-TokenDescription -String $_.URL)"

        $Arguments = @{
            Uri = $($_.URL).Trim()
            Force = $True
        }

        If (($_.AddToCrlCdp -eq $True) -and ($_.Protocol.ToLower() -eq "ldap")) {
            $Arguments.Add("AddToCrlCdp", $True)
        }elseif (($_.AddToCrlCdp -eq $True) -and ($_.Protocol.ToLower() -ne "ldap")) {
            Write-Line "CDP $(Get-TokenDescription -String $_.URL)" "Warning"
            Write-Line "--> AddToCrlCdp for protocol $(Get-TokenDescription -String $_.Protocol.ToLower())" "Warning"
            Write-Line "--> Unsupported configuration - ignoring..." "Warning"
            write-Line " "
        }
        If ($_.AddToCertificateCDP -eq $True) {
            $Arguments.Add("AddToCertificateCDP", $True)
        }
        If ($_.AddToFreshestCrl -eq $True) {
            $Arguments.Add("AddToFreshestCrl", $True)
        }
        If (($_.PublishToServer -eq $True) -and (($_.Protocol.ToLower() -ne "http") -and ($_.Protocol.ToLower() -ne "ftp"))) {
            $Arguments.Add("PublishToServer", $True)
        }elseIf (($_.PublishToServer -eq $True) -and (($_.Protocol.ToLower() -eq "http") -or ($_.Protocol.ToLower() -eq "ftp"))) {
            Write-Line "CDP $(Get-TokenDescription -String $_.URL)" "Warning"
            Write-Line "--> PublishToServer for protocol $(Get-TokenDescription -String $_.Protocol.ToLower())" "Warning"
            Write-Line "--> Unsupported configuration - ignoring..." "Warning"
        }
        If (($_.PublishDeltaToServer -eq $True) -and (($_.Protocol.ToLower() -ne "http") -and ($_.Protocol.ToLower() -ne "ftp"))) {
            $Arguments.Add("PublishDeltaToServer", $True)
        }elseIf (($_.PublishDeltaToServer -eq $True) -and (($_.Protocol.ToLower() -eq "http") -or ($_.Protocol.ToLower() -eq "ftp"))) {
            Write-Line "CDP $(Get-TokenDescription -String $_.URL)" "Warning"
            Write-Line "--> PublishDeltaToServer for protocol $(Get-TokenDescription -String $_.Protocol.ToLower())" "Warning"
            Write-Line "--> Unsupported configuration - ignoring..." "Warning"
        }
        If ($_.AddToCrlIdp -eq $True) {
            $Arguments.Add("AddToCrlIdp", $True)
        }

        Add-CaCrlDistributionPoint @Arguments | Out-Null
    }

    # Clearing the existing AIA Configuration, leaving only the default local Path
    Get-CaAuthorityInformationAccess | Where { !($_.Uri -match "\\") } | Foreach-Object {
        Write-Line "Removing AIA $($_.Uri)"
        Remove-CaAuthorityInformationAccess $_.Uri -Force | Out-Null
    }

    # Filling the specified AIA Paths in the desired order
    $Config.Config.CA.Settings.Extensions.AIA | ForEach-Object {

        $Url = $_.URL
        Write-Line "Adding AIA $(Get-TokenDescription -String $_.URL)"

        $Arguments = @{
            Uri = $($_.URL).Trim()
            Force = $True
        }

        If ($_.Protocol.ToLower() -eq "ocsp") {

            # Allow Renewing OCSP Response Signing Certificates with an Existing Key
            # https://technet.microsoft.com/en-us/library/cc754774(v=ws.11).aspx
            Run-MonitoredCommand -Command "certutil -setreg CA\UseDefinedCACertInRequest 1"

            $Arguments.Add("AddToCertificateOcsp", $True)

        } Else {

            $Arguments.Add("AddToCertificateAia", $True)
        }

        Add-CaAuthorityInformationAccess @Arguments | Out-Null
    }
}

