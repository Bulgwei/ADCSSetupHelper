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

Function Write-Config
{

    #
    # Print Config Summary
    #

    Write-Header -Text "CA Details:"

    Write-Line "Common Name:`n`t$($Config.Config.CA.Name)"
    Write-Line "Type:`n`t$($Config.Config.CA.Type)"
    Write-Line "Distinguished Name Suffix:`n`t$($Config.Config.CA.DistinguishedNameSuffix)"
    Write-Line "Database Directory:`n`t$($Config.Config.CA.DatabaseDirectory)"
    Write-Line "Database Log Directory:`n`t$($Config.Config.CA.LogDirectory)"
    Write-Line "Strict Compliance to Common PKI Standard:`n`t$($($Config.Config.CA.CertificateProfile -eq "CommonPki"))"
    Write-Line "Removing Microsoft specific certificate extensions:`n`t$($($Config.Config.CA.RemoveMSFTExtensions -eq "True"))"
    Write-Line "Enable custom subject formats:`n`t$($($Config.Config.CA.IncludeNonDefinedRDN -eq "True"))"

    If ($Config.CA.Type -eq "StandAloneRootCA") {
	    Write-Line "Configuration Partition:`n`t$($Config.Config.CA.DsConfigDn)"
        Write-Line "Validity Period for the CA Certificate:`n`t$($Config.Config.CA.Certificate.ValidityPeriodUnits) $($Config.Config.CA.Certificate.ValidityPeriod)"
    }

    Write-Line "Validity Period for issued Certificates:`n`t$($Config.Config.CA.Settings.ValidityPeriodUnits) $($Config.Config.CA.Settings.ValidityPeriod)"
    Write-Line "AuditFilter:`n`t$($Config.Config.CA.Settings.AuditFilter)"
    Write-Line "Administrator Interaction allowed during Service start:`n`t$($($Config.Config.CA.AllowAdministratorInteraction -eq "True"))"

    Write-Header -Text "CA Policies and Constraints:"

    Write-Line "Path Length Constraint:`n`t$($Config.Config.CA.Policy.PathLength) $(If ($Config.Config.CA.Type -eq "StandaloneRootCA") { "(virtual)" })"

    If ($Config.Config.CA.Policy.IssuancePolicy) {
        Write-Line " "
        Write-Line "Issuance Policies:"
        $Config.Config.CA.Policy.IssuancePolicy | ForEach-Object {
            Write-Line "`t$($_.Oid) ($($_.Description))"
        }
    }

    If ($Config.Config.CA.Policy.EnhancedKeyUsage) {
        Write-Line " "
        Write-Line "Enhanced Key Usages:"
        $Config.Config.CA.Policy.EnhancedKeyUsage | ForEach-Object {
            Write-Line "`t$($_.Oid) ($($_.Description))"
        }
    }

    Write-Header -Text "Crypto Parameters:"

    Write-Line "Name of KSP to Use:`n`t$($Config.Config.CA.Crypto.KspName)"
    Write-Line "Public/Private Key Algorithm:`n`t$($Config.Config.CA.Crypto.KeyAlgorithm)"
    Write-Line "Public/Private Key Length:`n`t$($Config.Config.CA.Crypto.KeyLength) Bits"
    Write-Line "Encryption KSP Name:`n`t$($Config.Config.CA.Crypto.EncryptionCspName)"
    Write-Line "PKCS#1 Version to use for Signing Operations:`n`t$($Config.Config.CA.Crypto.Pkcs1Version)"
    Write-Line "Signature Hash Algorithm:`n`t$($Config.Config.CA.Crypto.SignatureHashAlgorithm)"

    Write-Header -Text "CDP Configuration:"

    Write-Line "Protocol HTTP:"
    $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "http"} | ForEach-Object {
        Write-Line "`t$(Get-TokenDescription -String $_.URL)"

        Write-Line "`t- Publish CRLs to this location: $($_.PublishToServer)"
        Write-Line "`t- Include in all CRLs (for publication in AD): $($_.AddToCrlCdp)"
        Write-Line "`t- Include in CRLs (to find Delta CRLs): $($_.AddToFreshestCrl)"
        Write-Line "`t- Include in the CDP extension of issued certificates: $($_.AddToCertificateCDP)"
        Write-Line "`t- Publish Delta CRLs to this location: $($_.PublishDeltaToServer)"
        Write-Line "`t- Include in the IDP Extension of issued CRLs: $($_.AddToCrlIdp)"
    }
    Write-Line " "
    Write-Line "Protocol LDAP:"
    $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "ldap"} | ForEach-Object {
        Write-Line "`t$(Get-TokenDescription -String $_.URL)"

        Write-Line "`t- Publish CRLs to this location: $($_.PublishToServer)"
        Write-Line "`t- Include in all CRLs (for publication in AD): $($_.AddToCrlCdp)"
        Write-Line "`t- Include in CRLs (to find Delta CRLs): $($_.AddToFreshestCrl)"
        Write-Line "`t- Include in the CDP extension of issued certificates: $($_.AddToCertificateCDP)"
        Write-Line "`t- Publish Delta CRLs to this location: $($_.PublishDeltaToServer)"
        Write-Line "`t- Include in the IDP Extension of issued CRLs: $($_.AddToCrlIdp)"
    }
    Write-Line " "
    Write-Line "Protocol File:"
    $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "file"} | ForEach-Object {
        Write-Line "`t$(Get-TokenDescription -String $_.URL)"

        Write-Line "`t- Publish CRLs to this location: $($_.PublishToServer)"
        Write-Line "`t- Include in all CRLs (for publication in AD): $($_.AddToCrlCdp)"
        Write-Line "`t- Include in CRLs (to find Delta CRLs): $($_.AddToFreshestCrl)"
        Write-Line "`t- Include in the CDP extension of issued certificates: $($_.AddToCertificateCDP)"
        Write-Line "`t- Publish Delta CRLs to this location: $($_.PublishDeltaToServer)"
        Write-Line "`t- Include in the IDP Extension of issued CRLs: $($_.AddToCrlIdp)"
    }
    Write-Line " "

    Write-Header -Text "AIA Configuration:"

    Write-Line "Protocol HTTP:"
    $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "http"} | ForEach-Object { Write-Host "`t$(Get-TokenDescription -String $_.URL)"}
    Write-Line " "
    Write-Line "Protocol LDAP:"
    $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "ldap"} | ForEach-Object { Write-Host "`t$(Get-TokenDescription -String $_.URL)"}
    Write-Line " "
    Write-Line "Protocol OCSP:"
    $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "ocsp"} | ForEach-Object { Write-Host "`t$(Get-TokenDescription -String $_.URL)"}
    Write-Line " "

    Write-Header -Text "CRL Configuration:"

    Write-Line "Base CRL Validity:`n`t$($Config.Config.CA.Settings.CRL.PeriodUnits) $($Config.Config.CA.Settings.CRL.Period)"
    Write-Line "CRL Overlap Interval:`n`t$($Config.Config.CA.Settings.CRL.OverlapUnits) $($Config.Config.CA.Settings.CRL.OverlapPeriod)"
    Write-Line "Delta CRL Validity:`n`t$($Config.Config.CA.Settings.CRL.DeltaPeriodUnits) $($Config.Config.CA.Settings.CRL.DeltaPeriod)"
    Write-Line "Delta CRL Overlap Interval:`n`t$($Config.Config.CA.Settings.CRL.DeltaOverlapUnits) $($Config.Config.CA.Settings.CRL.DeltaOverlapPeriod)"

    Write-Header -Text "CA Policy File:"

    $CaPolicy

}

Function Write-Config2Window
{
    #
    # Print Config Summary
    #

    $CnfText = (Gen-Header -Text "CA Details:")

    $CnfText+= "Common Name:`n`t`t`t`t`t`t$($Config.Config.CA.Name)`r`n"
    $CnfText+= "Type:`n`t`t`t`t`t`t`t$($Config.Config.CA.Type)`r`n"
    $CnfText+= "Distinguished Name Suffix:`n`t`t`t`t$($Config.Config.CA.DistinguishedNameSuffix)`r`n"
    $CnfText+= "Database Directory:`n`t`t`t`t`t$($Config.Config.CA.DatabaseDirectory)`r`n"
    $CnfText+= "Database Log Directory:`n`t`t`t`t`t$($Config.Config.CA.LogDirectory)`r`n"
    $CnfText+= "Strict Compliance to Common PKI Standard:`n`t`t$($($Config.Config.CA.CertificateProfile -eq "CommonPki"))`r`n"
    $CnfText+= "Removing Microsoft specific certificate extensions:`n`t$($($Config.Config.CA.RemoveMSFTExtensions -eq "True"))`r`n"
    $CnfText+= "Enable custom subject formats:`n`t`t`t`t$($($Config.Config.CA.IncludeNonDefinedRDN -eq "True"))`r`n"

    If ($Config.CA.Type -eq "StandAloneRootCA") {
	    $CnfText+= "Configuration Partition:`n`t$($Config.Config.CA.DsConfigDn)`r`n"
        $CnfText+= "Validity Period for the CA Certificate:`n`t$($Config.Config.CA.Certificate.ValidityPeriodUnits) $($Config.Config.CA.Certificate.ValidityPeriod)`r`n"
    }

    $CnfText+= "Validity Period for issued Certificates:`n`t`t$($Config.Config.CA.Settings.ValidityPeriodUnits) $($Config.Config.CA.Settings.ValidityPeriod)`r`n"
    $CnfText+= "AuditFilter:`n`t`t`t`t`t`t$($Config.Config.CA.Settings.AuditFilter)`r`n"
    $CnfText+= "Administrator Interaction allowed during Service start:`n`t$($($Config.Config.CA.AllowAdministratorInteraction -eq "True"))`r`n"

    $CnfText+= (Gen-Header -Text "CA Policies and Constraints:")

    $CnfText+= "Path Length Constraint:`n`t$($Config.Config.CA.Policy.PathLength) $(If ($Config.Config.CA.Type -eq "StandaloneRootCA") { "(virtual)" })`r`n"

    If ($Config.Config.CA.Policy.IssuancePolicy) {
        $CnfText+= " `r`n"
        $CnfText+= "Issuance Policies:`r`n"
        $Config.Config.CA.Policy.IssuancePolicy | ForEach-Object {
            $CnfText+= "`t$($_.Oid) ($($_.Description))`r`n"
        }
    }

    If ($Config.Config.CA.Policy.EnhancedKeyUsage) {
        $CnfText+= " `r`n"
        $CnfText+= "Enhanced Key Usages:`r`n"
        $Config.Config.CA.Policy.EnhancedKeyUsage | ForEach-Object {
            $CnfText+= "`t$($_.Oid) ($($_.Description))`r`n"
        }
    }

    $CnfText+= (Gen-Header -Text "Crypto Parameters:")

    $CnfText+= "Name of KSP to Use:`n`t`t`t`t$($Config.Config.CA.Crypto.KspName)`r`n"
    $CnfText+= "Public/Private Key Algorithm:`n`t`t`t$($Config.Config.CA.Crypto.KeyAlgorithm)`r`n"
    $CnfText+= "Public/Private Key Length:`n`t`t`t$($Config.Config.CA.Crypto.KeyLength) Bits`r`n"
    $CnfText+= "Encryption KSP Name:`n`t`t`t`t$($Config.Config.CA.Crypto.EncryptionCspName)`r`n"
    $CnfText+= "PKCS#1 Version to use for Signing Operations:`n`t$($Config.Config.CA.Crypto.Pkcs1Version)`r`n"
    $CnfText+= "Signature Hash Algorithm:`n`t`t`t$($Config.Config.CA.Crypto.SignatureHashAlgorithm)`r`n"

    $CnfText+= (Gen-Header -Text "CDP Configuration:")

    $CnfText+= "Protocol HTTP:`r`n"
    $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "http"} | ForEach-Object {
        $CnfText+= "`t$(Get-TokenDescription -String $_.URL)`r`n"

        $CnfText+= "`t- Publish CRLs to this location: $($_.PublishToServer)`r`n"
        $CnfText+= "`t- Include in all CRLs (for publication in AD): $($_.AddToCrlCdp)`r`n"
        $CnfText+= "`t- Include in CRLs (to find Delta CRLs): $($_.AddToFreshestCrl)`r`n"
        $CnfText+= "`t- Include in the CDP extension of issued certificates: $($_.AddToCertificateCDP)`r`n"
        $CnfText+= "`t- Publish Delta CRLs to this location: $($_.PublishDeltaToServer)`r`n"
        $CnfText+= "`t- Include in the IDP Extension of issued CRLs: $($_.AddToCrlIdp)`r`n"
    }
    $CnfText+= " `r`n"
    $CnfText+= "Protocol LDAP:`r`n"
    $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "ldap"} | ForEach-Object {
        $CnfText+= "`t$(Get-TokenDescription -String $_.URL)`r`n"

        $CnfText+= "`t- Publish CRLs to this location: $($_.PublishToServer)`r`n"
        $CnfText+= "`t- Include in all CRLs (for publication in AD): $($_.AddToCrlCdp)`r`n"
        $CnfText+= "`t- Include in CRLs (to find Delta CRLs): $($_.AddToFreshestCrl)`r`n"
        $CnfText+= "`t- Include in the CDP extension of issued certificates: $($_.AddToCertificateCDP)`r`n"
        $CnfText+= "`t- Publish Delta CRLs to this location: $($_.PublishDeltaToServer)`r`n"
        $CnfText+= "`t- Include in the IDP Extension of issued CRLs: $($_.AddToCrlIdp)`r`n"
    }
    $CnfText+= " `r`n"
    $CnfText+= "Protocol File:`r`n"
    $Config.Config.CA.Settings.Extensions.CDP | Where { $_.Protocol -eq "file"} | ForEach-Object {
        $CnfText+= "`t$(Get-TokenDescription -String $_.URL)`r`n"

        $CnfText+= "`t- Publish CRLs to this location: $($_.PublishToServer)`r`n"
        $CnfText+= "`t- Include in all CRLs (for publication in AD): $($_.AddToCrlCdp)`r`n"
        $CnfText+= "`t- Include in CRLs (to find Delta CRLs): $($_.AddToFreshestCrl)`r`n"
        $CnfText+= "`t- Include in the CDP extension of issued certificates: $($_.AddToCertificateCDP)`r`n"
        $CnfText+= "`t- Publish Delta CRLs to this location: $($_.PublishDeltaToServer)`r`n"
        $CnfText+= "`t- Include in the IDP Extension of issued CRLs: $($_.AddToCrlIdp)`r`n"
    }
    $CnfText+= " `r`n"

    $CnfText+= (Gen-Header -Text "AIA Configuration:")

    $CnfText+= "Protocol HTTP:`r`n"
    $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "http"} | ForEach-Object { $CnfText+= "`t$(Get-TokenDescription -String $_.URL)`r`n"}
    $CnfText+= " `r`n"
    $CnfText+= "Protocol LDAP:`r`n"
    $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "ldap"} | ForEach-Object { $CnfText+= "`t$(Get-TokenDescription -String $_.URL)`r`n"}
    $CnfText+= " `r`n"
    $CnfText+= "Protocol OCSP:`r`n"
    $Config.Config.CA.Settings.Extensions.AIA | Where { $_.Protocol -eq "ocsp"} | ForEach-Object { $CnfText+= "`t$(Get-TokenDescription -String $_.URL)`r`n"}
    $CnfText+= " `r`n"

    $CnfText+= (Gen-Header -Text "CRL Configuration:")

    $CnfText+= "Base CRL Validity:`n`t`t$($Config.Config.CA.Settings.CRL.PeriodUnits) $($Config.Config.CA.Settings.CRL.Period)`r`n"
    $CnfText+= "CRL Overlap Interval:`n`t`t$($Config.Config.CA.Settings.CRL.OverlapUnits) $($Config.Config.CA.Settings.CRL.OverlapPeriod)`r`n"
    $CnfText+= "Delta CRL Validity:`n`t`t$($Config.Config.CA.Settings.CRL.DeltaPeriodUnits) $($Config.Config.CA.Settings.CRL.DeltaPeriod)`r`n"
    $CnfText+= "Delta CRL Overlap Interval:`n`t$($Config.Config.CA.Settings.CRL.DeltaOverlapUnits) $($Config.Config.CA.Settings.CRL.DeltaOverlapPeriod)`r`n"

    $CnfText+= (Gen-Header -Text "CA Policy File:")

    $CnfText+= $CaPolicy

    Show-Window -Title "OAADCS CA Setup Helper" -Comment "CA Setup Configuration ..." -Text $CnfText -height 700 -PrintWindow -AddVScrollBar|Out-Null
}

