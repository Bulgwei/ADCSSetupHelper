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

Function Check-SetupStatus
{
# can have several stati: "Blank"; "InProgress"; "AlreadyInstalled"
    if(!(Test-RegistryValue -Path $RegistryRoot -Value Active)){
        # box is clean install
        $Stat="Blank"
    }elseif((Parse-SetupStatus) -eq "0"){
        # CA is operational
        $Stat="AlreadyInstalled"
    }else{
        # CA is waiting for cert to be installed
        $Stat="InProgress"
    }
    return $Stat
}

Function Check-OSPreReqs
{
    Write-Header -Text "Prerequisites Check:"

    # Ensuring the Script will be run on a supported Operating System
    # ProductType = 3 means Server, see https://msdn.microsoft.com/en-us/library/aa394239(v=vs.85).aspx
    Write-Line "Check: Script is executed on Windows Server 2012 or newer OS."
    $OsData = Get-WmiObject Win32_OperatingSystem
    If (([int32]$OsData.BuildNumber -lt 9200) -or ([int32]$OsData.ProductType -ne 3)) {
        Write-Line "`tFailed: The Script must be run on Windows Server 2012 or newer!" "Error"
        $global:ShowStopper = $True
    } Else {
        Write-Line "`tPassed!" "Success"
    }
    Write-Line "Check: Looking if system proxy has been configured."
    $proxy=netsh winhttp show proxy
    if(!($proxy -match "no proxy server")){
        $global:ShowStopper = $True
        Write-Line "`tFailed: Configured system proxy found!" "Error"
    } Else {
        Write-Line "`tPassed!" "Success"
    }
}

Function Check-ScriptRequirements {
    Write-Line "Making sure this script is running in FullLanguage mode"
    if ($ExecutionContext.SessionState.LanguageMode -ne [System.Management.Automation.PSLanguageMode]::FullLanguage)
    {
        $errMsg = "This script must run in FullLanguage mode, but is running in " + $ExecutionContext.SessionState.LanguageMode.ToString()
        Write-Line $errMsg "Error"
        Return $false
    }
    Return $true
}

function Get-EnrollSrvEffectivePermission
{
    $IDs = $Global:User.Groups | %{$_.Translate([Security.Principal.NTAccount])}
    $IDs += $Global:User.Name
    $filter = "(CN=Enrollment Services)"
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Public Key Services,CN=Services,"+$ConfigContext
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $Container = $ds.Findone().GetDirectoryEntry() | %{$_}
    $Accesses = @()
    $Accesses += $Container.ObjectSecurity.Access | %{
        $current = $_
        $Rights = @($current.ActiveDirectoryRights.ToString().Split(",",[StringSplitOptions]::RemoveEmptyEntries) | %{$_.trim()})
        $GUID = $current.ObjectType.ToString()
        $current | Add-Member -Name Permission -MemberType NoteProperty -Value @()
        if ($Rights -contains "GenericRead") {$current.Permission += "Read"}
        if (($Rights -contains "WriteDacl") -or ($Rights -contains "GenericWrite")) {$current.Permission += "Write"}
        if ($Rights -contains "GenericAll") {$current.Permission += "Full Control"}
        $current
    }
    $EffectiveDeny = $Accesses | Where-Object {$_.AccessControlType -eq "Deny"} | ForEach-Object {
        if ($IDs -contains $_.IdentityReference.ToString()) {
            $_.Permission
        }
    }
    $EffectiveAllow = $Accesses | Where-Object {($_.AccessControlType -eq "Allow") -and (($_.Permission -contains "Full Control") -or ($_.Permission -contains "Write"))} | ForEach-Object {
        if ($IDs -contains $_.IdentityReference.ToString()) {
            $_.Permission
        }
    }
    $EffectiveDeny = $EffectiveDeny | Select-Object -Unique
    $EffectiveAllow = $EffectiveAllow | Select-Object -Unique
    return ($EffectiveAllow | Where-Object {$EffectiveDeny -notcontains $_})
}

Function Check-AccountPreReqs
{
    # Ensuring the Script will be run with Elevation
    Write-Line "Check: Current User has local administrative rights."
    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Line "`tFailed: The Script must be run with administrative rights, and with Elevation!" "Error"
        $global:ShowStopper = $True
    } Else {
        Write-Line "`tPassed!" "Success"
    }
    if($Config.Config.CA.Type -eq "EnterpriseSubordinateCA"){
        Write-Line "Check: Current User has write permission in Enrollment Services container."
        $Perms=Get-EnrollSrvEffectivePermission
        if($Perms.GetType().basetype.name -eq "Array"){
        # returned permissions in array format
            if(($perms.ToLower() -notcontains "write") -and ($perms.ToLower() -notcontains "full control")){
                Write-Line "`tFailed: The Script must be run with permission to write into Enrollment Services Container!" "Error"
                $global:ShowStopper = $True
            } Else {
                Write-Line "`tPassed!" "Success"
            }
        }elseif(!$Perms){
        # no permissions has been returned
                Write-Line "`tFailed: Could not enumarate permissions on Enrollment Services Container!" "Error"
                $global:ShowStopper = $True
        }else{
        # returned permissions in string format (only one ACL entry has been returned)
            if(($perms.ToLower() -notmatch "write") -and ($perms.ToLower() -notmatch "full control")){
                Write-Line "`tFailed: The Script must be run with permission to write into Enrollment Services Container!" "Error"
                $global:ShowStopper = $True
            } Else {
                Write-Line "`tPassed!" "Success"
            }
        } 
    }
}

function Check-CaObjectExist
{
    #if computer is standalone, don't check anything in AD
    if((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
        Write-Line "Check: CA enrollment object exist in Enrollment Services container."
        $filter = "(cn=$($Config.Config.CA.Name))"
        $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $ConfigContext = "CN=Enrollment Services,CN=Public Key Services,CN=Services,"+$ConfigContext
        $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext","$filter")
        $CaObject = $ds.Findone()
        If ($CaObject) {
            Write-Line "`tFailed: The CA object $Config.CA.Name already exist in Enrollment Services!" "Error"
            $global:ShowStopper = $True
        } Else {
            Write-Line "`tPassed!" "Success"
        }
    }
}

Function Configure-Prereqs
{
    # Checking if Interactive Services Detection is enabled
    If ($Config.Config.CA.AllowAdministratorInteraction -eq "True") {

        If (Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Windows" -Value NoInteractiveServices) {
            $NoInteractiveServices = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Windows" -Name NoInteractiveServices).NoInteractiveServices
        } Else {
            $NoInteractiveServices = 1
        }

        # Checking again because we would exit entirely with a "Return"
        # If Interactive Services Detection is not enabled, we must reboot
        If ($NoInteractiveServices -ne 0) {

            # Setting the correct value for Interactive Services Detection
            Write-Line "Enabling Interactive Services Detection. This requires rebooting the machine before we continue." "Warning"
            Write-Line "Run the Script again after the Reboot." "Warning"
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Windows" /v "NoInteractiveServices" /d 0 /t REG_DWORD /f

            # Rebooting the Machine to load the new value
            Write-Line "Rebooting in 60 Seconds. Press Ctrl-C to abort!" "Warning"
            Start-Sleep 60
            Restart-Computer -Force

            # Just to be sure
            Return
        }
    }
}
