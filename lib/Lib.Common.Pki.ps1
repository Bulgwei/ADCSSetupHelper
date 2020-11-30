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

# uwe.gradenegger@microsoft.com & andreas.luy@microsoft.com
# 04.11.2019

Function Get-TokenDescription {

    # Replaces Tokens with a meaningful name
    # This is just for convenience to get a better readable Log

    param (
        [Parameter(Mandatory=$True) ] [string]$String
    )

    # Two-Digit Numbers before one-digit numbers!
    $String = $($String.Replace("%10","<CDPObjectClass>"))
    $String = $($String.Replace("%11","<CAObjectClass>"))

    $String = $($String.Replace("%1","<ServerDNSName>"))
    $String = $($String.Replace("%2","<ServerShortName>"))
    $String = $($String.Replace("%3","<CAName>"))
    $String = $($String.Replace("%4","<CertificateName>"))
    $String = $($String.Replace("%6","<ConfigurationContainer>"))
    $String = $($String.Replace("%7","<CATruncatedName>"))
    $String = $($String.Replace("%8","<CRLNameSuffix>"))
    $String = $($String.Replace("%9","<DeltaCRLAllowed>"))


    return $String
}

Function Get-CaPolicy {

    # Automagically building a CApolicy.inf

    param (
        [Parameter(Mandatory=$True) ] [Xml]$Config
    )
#region capolicy.inf header
    $CaPolicy = ''
    $CaPolicy += "; =============================================================================================`r`n"
    $CaPolicy += "; THIS SAMPLE IS PROVIDED ""AS IS"" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED`r`n"
    $CaPolicy += "; OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR`r`n"
    $CaPolicy += "; FITNESS FOR A PARTICULAR PURPOSE.`r`n"
    $CaPolicy += ";`r`n"
    $CaPolicy += "; This sample is not supported under any Microsoft standard support program or service.`r`n"
    $CaPolicy += "; The script is provided AS IS without warranty of any kind. Microsoft further disclaims all`r`n"
    $CaPolicy += "; implied warranties including, without limitation, any implied warranties of merchantability`r`n"
    $CaPolicy += "; or of fitness for a particular purpose. The entire risk arising out of the use or`r`n"
    $CaPolicy += "; performance of the sample and documentation remains with you. In no event shall Microsoft,`r`n"
    $CaPolicy += "; its authors, or anyone else involved in the creation, production, or delivery of the script`r`n" 
    $CaPolicy += "; be liable for any damages whatsoever (including, without limitation, damages for loss of`r`n"
    $CaPolicy += "; business profits, business interruption, loss of business information, or other pecuniary`r`n" 
    $CaPolicy += "; loss) arising out of the use of or inability to use the sample or documentation, even if`r`n" 
    $CaPolicy += "; Microsoft has been advised of the possibility of such damages.`r`n"
    $CaPolicy += "; =============================================================================================`r`n"
    $CaPolicy += "`r`n"
    $CaPolicy += "[Version]`r`n"
    $CaPolicy += "Signature=""`$Windows NT$""`r`n"
    $CaPolicy += "`r`n"
#endregion

#region certificate configuration based on certificate profile
    # possible values are:
    # - empty equals Default: markes KeyUsage Extension as "Critical"
    # Default:                markes KeyUsage Extension as "Critical"
    # Microsoft:              markes KeyUsage Extension as "Critical"
    # Microsoft Legacy:       leaves KeyUsage Extension uncritical
    # CommonPKI:              removes "Digital Signature" and markes KeyUsage Extension as "Critical"

    If (($Config.Config.CA.CertificateProfile).toLower() -eq "commonpki") {
        # Extensions
        $CaPolicy += "[Extensions]`r`n"
        $CaPolicy += "`r`n"
        $CaPolicy += "; Compliance to Common PKI (formerly ISIS-MTT) Standard`r`n"
        $CaPolicy += "; - Key Usage Extension marked as Critical`r`n"
        $CaPolicy += "; - Key Usage Extension will be Stripped of DigitalSignature (leaving only KeyCertSign and CrlSign)`r`n"
        $CaPolicy += "; Refer to https://support.microsoft.com/en-us/kb/888180`r`n"
        $CaPolicy += "2.5.29.15 = AwIBBg==`r`n"
        $CaPolicy += "Critical = 2.5.29.15`r`n"
        $CaPolicy += "`r`n"
    }elseif(($Config.Config.CA.CertificateProfile).toLower() -ne "microsoft-legacy") {
        $CaPolicy += "[Extensions]`r`n"
        $CaPolicy += "`r`n"
        $CaPolicy += "; RFC5280 recommendation`r`n"
        $CaPolicy += "; - Key Usage Extension marked as Critical`r`n"
        $CaPolicy += "2.5.29.15 = AwIBhg==`r`n"
        $CaPolicy += "Critical = 2.5.29.15`r`n"
        $CaPolicy += "`r`n"
    }
    If ($Config.Config.CA.RemoveMSFTExtensions -ne $null) {
        If (($Config.Config.CA.RemoveMSFTExtensions).ToLower() -eq "true") {
            $CaPolicy += "; Removing Microsoft specific Certificate Extensions`r`n"
            $CaPolicy += "; Refer to https://support.microsoft.com/de-de/help/287547/object-ids-associated-with-microsoft-cryptography`r`n"
            $CaPolicy += "1.3.6.1.4.1.311.21.1= ; szOID_CERTSRV_CA_VERSION`r`n"
            $CaPolicy += "1.3.6.1.4.1.311.21.2= ; szOID_CERTSRV_PREVIOUS_CERT_HASH`r`n"

            If ($Config.Config.CA.Type -eq "EnterpriseSubordinateCA") {
                $CaPolicy += "1.3.6.1.4.1.311.20.2= ; szOID_ENROLL_CERTTYPE_EXTENSION`r`n"
            }

            $CaPolicy += "`r`n"
        }
    }
#endregion

    # PolicyStatementExtension
    #
    # To Do: Certificate Policies
    # Support for the AnyPolicy Qualifier
    #
    If ($Config.Config.CA.Policy.IssuancePolicy) {

        $i = 1
        $Config.Config.CA.Policy.IssuancePolicy | ForEach-Object {


            $CaPolicy += "; $($_.Description)`r`n"
            $CaPolicy += "[IssuancePolicy$($i)]`r`n"
            $CaPolicy += "OID=$($_.Oid)`r`n"
            If ($($_.Notice)) {
	            $CaPolicy += "Notice=$($_.Notice)`r`n"
            }
            If ($($_.Url)) {
	            $CaPolicy += "URL=$($_.Url)`r`n"
            }
            $CaPolicy += "`r`n"
            $i++

        }

        $CaPolicy += "[PolicyStatementExtension]`r`n"
        $CaPolicy += "Policies="
    
        $j = if($i-1 -le 0){[int32]0}else{$i-1}
        For ($k=1; $k -le $j; $k++) {
    
            $CaPolicy += "IssuancePolicy$($k)"
            If ($k -lt $j) {
                $CaPolicy += ","
            }

        }
        $CaPolicy += "`r`n"
        $CaPolicy += "`r`n"
    }

    If ($Config.Config.CA.Type -eq "EnterpriseSubordinateCA") {
        If ($Config.Config.CA.Policy.PathLength) {
            # BasicConstraintsExtension
            $CaPolicy += "[BasicConstraintsExtension]`r`n"
            $CaPolicy += "PathLength=$($Config.Config.CA.Policy.PathLength)`r`n"
            $CaPolicy += "Critical=TRUE`r`n"
            $CaPolicy += "`r`n"
        }
    }

    If ($Config.Config.CA.Policy.EnhancedKeyUsage) {
        $CaPolicy += "; The following lines define the trustworthy EKUs for the CA certificate.`r`n"
        $CaPolicy += "; We recommend to mark this extension as critical if used to ensure, it`r`n"
        $CaPolicy += "; will be enforced.`r`n"

        $CaPolicy += "[EnhancedKeyUsageExtension]`r`n"
        $Config.Config.CA.Policy.EnhancedKeyUsage | ForEach-Object {
            $CaPolicy += "OID=$($_.Oid) ; $($_.Description)`r`n"
        }
        If ($Config.Config.CA.Policy.EKUmArkCritical){
            $CaPolicy += "Critical="+$(If(($Config.Config.CA.Policy.EKUmArkCritical).ToLower() -ne "true") {"false"}else{"true"})+"`r`n"
        }else{
            $CaPolicy += "Critical=false`r`n"
            $CaPolicy += "; The Enhanced Key Usage Extension of the Certificate`r`n"
            $CaPolicy += "; will be marked as non-critical due to the business`r`n"
            $CaPolicy += "; decision to favor compatibility over security.`r`n"
        }

        $CaPolicy += "`r`n"
    }

    #
    # To Do:
    # - Name Constraints
    #

    # CertSrv_Server
    $CaPolicy += "[Certsrv_Server]`r`n"
    $CaPolicy += "`r`n"

    $CaPolicy += "; The following Settings will only have effect on CA Certificate renewals`r`n"
    $CaPolicy += "RenewalKeyLength=$($Config.Config.CA.Crypto.KeyLength)`r`n"
    If ($Config.Config.CA.Type -eq "StandAloneRootCA") {
        $CaPolicy += "RenewalValidityPeriod=$($Config.Config.CA.Certificate.ValidityPeriod)`r`n"
        $CaPolicy += "RenewalValidityPeriodUnits=$($Config.Config.CA.Certificate.ValidityPeriodUnits)`r`n"
    }
    $CaPolicy += "`r`n"

    If ($Config.Config.CA.Type -eq "EnterpriseSubordinateCA") {
        $CaPolicy += "; LoadDefaultTemplates=0 will prevent the CA from instantly loading default `r`n"
        $CaPolicy += "; Certificate Templates after CA installation`r`n"
        $CaPolicy += "LoadDefaultTemplates=0`r`n"
        $CaPolicy += "`r`n"
    }

    If ($Config.Config.CA.Crypto.Pkcs1Version -eq "2.1") {
        $CaPolicy += "; AlternateSignatureAlgorithm=0 makes the CA use PKCS#1 1.5 for Signatures`r`n"
        $CaPolicy += "; AlternateSignatureAlgorithm=1 makes the CA use PKCS#1 2.1 for Signatures`r`n"
        $CaPolicy += "; From a security perspective, PKCS#1 2.1 is recommended.`r`n"
        $CaPolicy += "; However, many vendors (like Cisco) have not implemented PKCS#1 2.1, thus`r`n"
        $CaPolicy += "; their devices cannot understand certificates from a CA that signs with 2.1`r`n"
        $CaPolicy += "; For compatibility reasons, we will have to fall back to 1.5 in most cases`r`n"
        $CaPolicy += "; There are working attacks on 1.5, which are currently mitigated within`r`n"
        $CaPolicy += "; the actual products that use Certificates`r`n"
        $CaPolicy += "AlternateSignatureAlgorithm=1`r`n"
        $CaPolicy += "`r`n"
    }

    If (($Config.Config.CA.Type -eq "StandAloneRootCA") -and ($Config.Config.CA.CertificateProfile -eq "CommonPki")) {
        # Force Encoding of the Subject and Issuer of the Root CA Certificate with UTF-8
        $CaPolicy += "ForceUTF8=1`r`n"
        $CaPolicy += "`r`n"

    }

    return $CaPolicy

}