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


Function Check-KspAvailability
{

    # Checks if the Ksp specified in $Name is actually present on the local System
    # Returns $True if the Ksp is present and $False if not

    param (
        $Name
    )

    $Result = $False

    $KspList = certutil -csplist
    $KspList | ForEach-Object {
        If ($_ -match $Name) {
            $Result = $True
        }
    }
    Return $Result
}


function Check-SafeNetSlotAccess
{
    $MatchFound = $false
    Write-Line "Check: HSM slots are configured on the local System."
    $key = "HKLM:\SOFTWARE\Safenet\SafeNetKSP\Slots"
    if(!(Test-Path $key)){
        Write-Line "`tFailed: No configured slots for $($Config.Config.CA.Crypto.KspName) were not found on local registry!" "Error"
        $global:ShowStopper = $True
    }Else{
        Write-Host "Check: HSM Slots assigend to user: $($Global:User)."
        ((Get-ChildItem $key).name) | foreach{ if($_.tolower().Split("\") -match $Global:User){ $MatchFound = $true}}
        if(!$MatchFound){
            Write-Line "`tFailed: The current user does not have a slot at the HSM assigned!" "Error"
            $global:ShowStopper = $True
        }else{
            Write-Line "Found assigend HSM Slots for user: $($Global:User)!" "Success"
        }
    }
}


function Check-NcipherModuleAccess
{
    Write-Line "Check: HSM tools are found on the local System."
    $EnquiryPath= "$env:NFAST_HOME\bin\enquiry.exe"
    if(!(Test-Path $EnquiryPath)){
        Write-Line "`tFailed: Cannot locate nCipher HSM tools on the local System." "Error"
        Write-Line "`tFailed: Tools should be located at ""%NFAST_HOME%\bin""." "Error"
        $global:ShowStopper = $True
    }else{
        Write-Line "Running ""Enquiry"" to check module connectivity..."
        $result=cmd.exe /c $EnquiryPath
        $ErrorStat=($result|findstr "mode")
        if(!($ErrorStat -match "operational")){
            Write-Line "Verification of module connectivity failed with Enquiry:"
            Write-Line ("    " +$ErrorStat) "Error"
            Write-Line " "
            Write-Line "Review connectivity check in detail to identify the root cause!" "Warning"
            foreach ($line in $result){if($line){Write-Line ($line)}else{Write-Line " "}}
            Write-Line " "
            Write-Line "Double check HSM configuration and connectivity!" "Warning"
            Write-Line "Rerun script again, when issues have been fixed." "Warning"
            Write-Line "Setup stopped." "Warning"
            exit
        }
        Write-Line """Enquiry"" module check completed successfully!" "Success"


    }
}

Function Check-KSPPreReqs
{
    # Ensuring the specified Ksp is present
    Write-Line "Check: Specified Key Storage Provider for the CA Certificates is installed on the local System."
    Write-Line ("--> "+$Config.Config.CA.Crypto.KspName)
    If (-not (Check-KspAvailability -Name $Config.Config.CA.Crypto.KspName)) {
        Write-Line "`tFailed: The specified Key Storage Provider named $($Config.Config.CA.Crypto.KspName) was not found on the local System." "Error"
        $global:ShowStopper = $True
    } Else {
        if($Config.Config.CA.Crypto.KspName.ToLower() -match "safenet"){
            Check-SafeNetSlotAccess
        }elseif($Config.Config.CA.Crypto.KspName.ToLower() -match "ncipher"){
            Check-NcipherModuleAccess
        }
        Write-Line "`tPassed!" "Success"
    }

    # Ensuring the specified ecryption Ksp is present
    If ($Config.Config.CA.Crypto.EncryptionCspName) {
        Write-Line "Check: Specified Key Storage Provider for the CAExchange Certificates is installed in the local System."
        Write-Line ("--> "+$Config.Config.CA.Crypto.EncryptionCspName)
        If (-not (Check-KspAvailability -Name $Config.Config.CA.Crypto.EncryptionCspName)) {
            Write-Line "`tFailed: The specified Key Storage Provider named $($Config.Config.CA.Crypto.EncryptionCspName) was not found on the local System." "Error"
            $global:ShowStopper = $True 
        } Else {
            Write-Line "`tPassed!" "Success"
        }
    }
}

