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

$SuccessFontColor = "Green"
$WarningFontColor = "Yellow"
$FailureFontColor = "Red"

$SuccessBackColor = "Black"
$WarningBackColor = "Black"
$FailureBackColor = "Black"

$FontStdt = New-Object System.Drawing.Font("Arial",11,[System.Drawing.FontStyle]::Regular)
$FontBold = New-Object System.Drawing.Font("Arial",11,[System.Drawing.FontStyle]::Bold)
$FontItalic = New-Object System.Drawing.Font("Arial",9,[System.Drawing.FontStyle]::Italic)
$Icon = [system.drawing.icon]::ExtractAssociatedIcon("C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe")

Function Write-Header
{

    param (
        [Parameter(Mandatory=$True) ] [string]$Text
    )

    Write-Host ""
    Write-Host "------------------------------------------------------------------------------------------------"
    Write-Host $Text
    Write-Host "------------------------------------------------------------------------------------------------"
}

Function Write-Line
{
    param (
        [Parameter(Mandatory=$false) ] [string]$Text,
        [Parameter(Mandatory=$False) ] [string]$Type
    )

    $SuccessFontColor = "Green"
    $WarningFontColor = "Yellow"
    $FailureFontColor = "Red"

    $SuccessBackColor = "Black"
    $WarningBackColor = "Black"
    $FailureBackColor = "Black"
    
    switch ($Type.ToLower()) {
        "success" {
            $FontColor = $SuccessFontColor
            $BackColor = $SuccessBackColor
            }
        "warning" {
            $FontColor = $WarningFontColor
            $BackColor = $WarningBackColor
            }
        "error" {
            $FontColor = $FailureFontColor
            $BackColor = $FailureBackColor
            }
        default {
            $FontColor = "White"
            $BackColor = $SuccessBackColor
            }
    }
    # ensure we have something to write!!!
    if(!$Text){$Text=" "}

    Write-Host -ForegroundColor $FontColor -BackgroundColor $BackColor $Text
}

Function Run-MonitoredCommand
{

    param (
        [Parameter(Mandatory=$True) ] [string]$Command,
		[Parameter(Mandatory=$False) ] [array]$SuccessCode = @(0)
    )

    Write-Line " "
    Write-Line "Executing Command ""$($Command)""..."

    # Running the Command and handling each line of Command-Line Output
	cmd.exe /c $Command 2>&1 | Foreach-Object {

        # Output to Console
        Write-Host $($_.ToString())

    }
	
    $ReturnCode = $LASTEXITCODE

    # Have to replace these with a more generic function
    If (-not ($SuccessCode -contains $ReturnCode)) { 
        Write-Line "Command ""$($Command)"" failed" "Error"
    } Else {
        Write-Line "Command ""$($Command)"" executed successfully" "Success"
    }

}

function Break-MessageBox
{
    param(
        [Parameter(mandatory=$true)]$Message
    )
    Write-Line $Message "Error"
    Write-Line "Setup failed!" "Error"
   [void][System.Windows.Forms.MessageBox]::Show($Message,"Critical Error!","OK",[System.Windows.Forms.MessageBoxIcon]::Stop)
    exit
}

function Write-OAHeading
{
    Write-Line "------------------------------------------------------------------------------------------------"
    Write-Line " "
    Write-Line " Microsoft Onboarding Accelerator "
    Write-Line " Active Directory Certificate Services"
    Write-Line " Deployment & Migration"
    Write-Line " "
    Write-Line "------------------------------------------------------------------------------------------------"
    Write-Line " "
}

function Display-EULA
{
    $EulaText="`r`nTHIS SAMPLE IS PROVIDED ""AS IS"" WITHOUT WARRANTY OF ANY KIND, EITHER`r`n"
    $EulaText=$EulaText+"EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED`r`n"
    $EulaText=$EulaText+"WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.`r`n`r`n"
    $EulaText=$EulaText+"This sample is not supported under any Microsoft standard support program or service.`r`n"
    $EulaText=$EulaText+"The script is provided AS IS without warranty of any kind. Microsoft further disclaims all`r`n"
    $EulaText=$EulaText+"implied warranties including, without limitation, any implied warranties of merchantability`r`n"
    $EulaText=$EulaText+"or of fitness for a particular purpose. The entire risk arising out of the use or performance`r`n"
    $EulaText=$EulaText+"of the sample and documentation remains with you. In no event shall Microsoft, its authors,`r`n"
    $EulaText=$EulaText+"or anyone else involved in the creation, production, or delivery of the script be liable for`r`n" 
    $EulaText=$EulaText+"any damages whatsoever (including, without limitation, damages for loss of business profits,`r`n" 
    $EulaText=$EulaText+"business interruption, loss of business information, or other pecuniary loss) arising out of`r`n" 
    $EulaText=$EulaText+"the use of or inability to use the sample or documentation, even if Microsoft has been`r`n"
    $EulaText=$EulaText+"advised of the possibility of such damages.`r`n"


    $result=Show-Window -Title "OAADCS CA Setup Helper" -Comment "Agree EULA? If you don't agree with the below, setup will stop!" -Text $EulaText -width 1000 -height 460 -YesNoWindow -AlwaysTop $true
    
    $result=if($result -eq "YES"){$True}else{$False}

    return $result
}

function Select-ConfigFile
{
    $ConfigFileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        InitialDirectory = $BaseDirectory 
        Filter = 'ConfigFiles (*.xml)|*.xml'
    }
    [void] $ConfigFileBrowser.ShowDialog()
    return ($ConfigFileBrowser.filename)
}


Function Gen-Header
{

    param (
        [Parameter(Mandatory=$True) ] [string]$Text
    )

    $Text="`r`n---------------------------------------------------------------------------------------------`r`n"+
        $Text+"`r`n---------------------------------------------------------------------------------------------`r`n"
    return $Text
}


function Print-Text{

    param (
        [Parameter(Mandatory=$True) ] [string]$Text
        )
    $prnDlg=New-Object System.Windows.Forms.PrintDialog
    $prnDlg.ShowDialog()
    $SelPrt=$prnDlg.PrinterSettings.PrinterName
    $Text| Out-Printer -Name $SelPrt
}


function Show-Window
{
[CmdletBinding(DefaultParameterSetName="OKWindow")]
Param (
    [Parameter(Mandatory=$true,
        ParameterSetName="OKWindow")]
    [Parameter(Mandatory=$true,
        ParameterSetName="OKCancelWindow")]
    [Parameter(Mandatory=$true,
        ParameterSetName="YesNoWindow")]
    [Parameter(Mandatory=$true,
        ParameterSetName="PrintWindow")]
    [String]$Title,
    [Parameter(Mandatory=$false,
        ParameterSetName="OKWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="OKCancelWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="YesNoWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="PrintWindow")]
    [Switch]$AddVScrollBar,
    [Parameter(Mandatory=$false,
        ParameterSetName="OKWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="OKCancelWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="YesNoWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="PrintWindow")]
    [string]$Comment,
    [Parameter(Mandatory=$true,
        ParameterSetName="OKWindow")]
    [Parameter(Mandatory=$true,
        ParameterSetName="OKCancelWindow")]
    [Parameter(Mandatory=$true,
        ParameterSetName="YesNoWindow")]
    [Parameter(Mandatory=$true,
        ParameterSetName="PrintWindow")]
    [string]$Text,
    [Parameter(Mandatory=$false,
        ParameterSetName="OKWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="OKCancelWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="YesNoWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="PrintWindow")]
    [int32]$width,
    [Parameter(Mandatory=$false,
        ParameterSetName="OKWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="OKCancelWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="YesNoWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="PrintWindow")]
    [int32]$height,
    [Parameter(Mandatory=$false,
        ParameterSetName="OKWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="OKCancelWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="YesNoWindow")]
    [Parameter(Mandatory=$false,
        ParameterSetName="PrintWindow")]
    [boolean]$AlwaysTop,
    [Parameter(Mandatory=$false,
        ParameterSetName="OKWindow")]
    [Switch]$OKWindow,
    [Parameter(Mandatory=$false,
        ParameterSetName="OKCancelWindow")]
    [Switch]$OKCancelWindow,
    [Parameter(Mandatory=$false,
        ParameterSetName="YesNoWindow")]
    [Switch]$YesNoWindow,
    [Parameter(Mandatory=$false,
        ParameterSetName="PrintWindow")]
    [Switch]$PrintWindow
)

    if(!$width){$width=1000}
    if(!$height){$height=560}
    if(!$OKWindow -and !$OKCancelWindow -and !$YesNoWindow -and !$PrintWindow){$OKWindow=$true}

    $Script:text=$Text
    $Script:BtnResult=$null
    $Comment=%{if($Comment){$Comment}else{" "}}

    $objForm = New-Object System.Windows.Forms.Form 
    $objForm.Text = $Title
    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.AutoSize = $True
    $objTextBox = New-Object System.Windows.Forms.TextBox

    #region build UI
    $objForm.Topmost = %{if($AlwaysTop){$AlwaysTop}else{$False}}
    #$objForm.ControlBox = $false
    $objForm.FormBorderStyle = "FixedDialog"
    $objForm.StartPosition = "CenterScreen"
    $objForm.MinimizeBox = $False
    $objForm.MaximizeBox = $False
    $objForm.WindowState = "Normal"
    $objForm.Size = New-Object System.Drawing.Size($width,$height) 
    $objForm.BackColor = "White"
    $objForm.Icon = $Icon
    $objForm.Font = $FontStdt
    $objLabel.Location = New-Object System.Drawing.Size(10,10)
    $objLabel.Text = $Comment # "CA Setup Configuration ..."
    $objTextBox.Location = New-Object System.Drawing.Size(15,50)
    $objTextBox.Size = New-Object System.Drawing.Size(($width-40),($height-160))
    $objTextBox.MultiLine = $True
    $objTextBox.ScrollBars = %{if($AddVScrollBar){"Vertical"}else{"None"}}
    $objTextBox.Font= New-Object System.Drawing.Font("Courier New",12,[System.Drawing.FontStyle]::Bold)
    $objTextBox.ForeColor = [System.Drawing.Color]::Green
    $objTextBox.Text=$Text

    $objForm.Controls.Add($objLabel)
    $objForm.Controls.Add($objTextBox)

    if($OKWindow){
        $objBtnOk = New-Object System.Windows.Forms.Button
        $objBtnOk.Cursor = [System.Windows.Forms.Cursors]::Hand
        #$objBtnOk.BackColor = [System.Drawing.Color]::LightGreen
        #$objBtnOk.Font = New-Object System.Drawing.Font("Verdana",14,,[System.Drawing.FontStyle]::Bold)
        $objBtnOk.Location = New-Object System.Drawing.Size((($width/2)-40),($height-100))
        $objBtnOk.Size = New-Object System.Drawing.Size(80,40)
        $objBtnOk.Text = "OK"
        $objBtnOk.Add_Click({
            $script:BtnResult="OK"
            $objForm.Close()
            $objForm.dispose()
        })
        $objForm.Controls.Add($objBtnOk)
    }elseif($OKCancelWindow){
        $objBtnOk = New-Object System.Windows.Forms.Button
        $objBtnOk.Cursor = [System.Windows.Forms.Cursors]::Hand
        #$objBtnOk.BackColor = [System.Drawing.Color]::LightGreen
        #$objBtnOk.Font = New-Object System.Drawing.Font("Verdana",14,,[System.Drawing.FontStyle]::Bold)
        $objBtnOk.Location = New-Object System.Drawing.Size((($width/4)-40),($height-100))
        $objBtnOk.Size = New-Object System.Drawing.Size(80,40)
        $objBtnOk.Text = "OK"
        $objBtnOk.Add_Click({
            $script:BtnResult="OK"
            $objForm.Close()
            $objForm.dispose()
        })
        $objBtnCancel = New-Object System.Windows.Forms.Button
        $objBtnCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
        #$objBtnCancel.BackColor = [System.Drawing.Color]::LightGreen
        #$objBtnCancel.Font = New-Object System.Drawing.Font("Verdana",14,,[System.Drawing.FontStyle]::Bold)
        $objBtnCancel.Location = New-Object System.Drawing.Size(((($width/4)*3)-40),($height-100))
        $objBtnCancel.Size = New-Object System.Drawing.Size(80,40)
        $objBtnCancel.Text = "Cancel"
        $objBtnCancel.Add_Click({
            $script:BtnResult="CANCEL"
            $objForm.Close()
            $objForm.dispose()
        })
        $objBtnCancel.TabIndex=0
        $objForm.Controls.Add($objBtnOk)
        $objForm.Controls.Add($objBtnCancel)
    }elseif($YesNoWindow){
        $objBtnYes = New-Object System.Windows.Forms.Button
        $objBtnYes.Cursor = [System.Windows.Forms.Cursors]::Hand
        #$objBtnYes.BackColor = [System.Drawing.Color]::LightGreen
        #$objBtnYes.Font = New-Object System.Drawing.Font("Verdana",14,,[System.Drawing.FontStyle]::Bold)
        $objBtnYes.Location = New-Object System.Drawing.Size((($width/4)-40),($height-100))
        $objBtnYes.Size = New-Object System.Drawing.Size(80,40)
        $objBtnYes.Text = "Yes"
        $objBtnYes.Add_Click({
            $script:BtnResult="YES"
            $objForm.Close()
            $objForm.dispose()
        })
        $objBtnNo = New-Object System.Windows.Forms.Button
        $objBtnNo.Cursor = [System.Windows.Forms.Cursors]::Hand
        #$objBtnNo.BackColor = [System.Drawing.Color]::LightGreen
        #$objBtnNo.Font = New-Object System.Drawing.Font("Verdana",14,,[System.Drawing.FontStyle]::Bold)
        $objBtnNo.Location = New-Object System.Drawing.Size(((($width/4)*3)-40),($height-100))
        $objBtnNo.Size = New-Object System.Drawing.Size(80,40)
        $objBtnNo.Text = "No"
        $objBtnNo.Add_Click({
            $script:BtnResult="NO"
            $objForm.Close()
            $objForm.dispose()
        })
        $objBtnNo.TabIndex=0
        $objForm.Controls.Add($objBtnYes)
        $objForm.Controls.Add($objBtnNo)
    }else{ #$PrintWindow
        $objBtnOk = New-Object System.Windows.Forms.Button
        $objBtnOk.Cursor = [System.Windows.Forms.Cursors]::Hand
        #$objBtnOk.BackColor = [System.Drawing.Color]::LightGreen
        #$objBtnOk.Font = New-Object System.Drawing.Font("Verdana",14,,[System.Drawing.FontStyle]::Bold)
        $objBtnOk.Location = New-Object System.Drawing.Size((($width/4)-40),($height-100))
        $objBtnOk.Size = New-Object System.Drawing.Size(80,40)
        $objBtnOk.Text = "OK"
        $objBtnOk.Add_Click({
            $script:BtnResult="OK"
            $objForm.Close()
            $objForm.dispose()
        })
        $objBtnPrint = New-Object System.Windows.Forms.Button
        $objBtnPrint.Cursor = [System.Windows.Forms.Cursors]::Hand
        #$objBtnCancel.BackColor = [System.Drawing.Color]::LightGreen
        #$objBtnCancel.Font = New-Object System.Drawing.Font("Verdana",14,,[System.Drawing.FontStyle]::Bold)
        $objBtnPrint.Location = New-Object System.Drawing.Size(((($width/4)*3)-40),($height-100))
        $objBtnPrint.Size = New-Object System.Drawing.Size(80,40)
        $objBtnPrint.Text = "Print"
        $objBtnPrint.Add_Click({
            Print-Text $script:Text
            $script:BtnResult="OK"
            $objForm.Close()
            $objForm.dispose()
        })
        $objBtnPrint.TabIndex=0
        $objForm.Controls.Add($objBtnOk)
        $objForm.Controls.Add($objBtnPrint)
    }

    $objForm.Add_Shown({$objForm.Activate()})
    [void]$objForm.ShowDialog()
    #endregion
    return $BtnResult
}


