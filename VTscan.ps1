<#
Tool: VirusTotal Hash Scanner
Description: This PowerShell script provides a simple GUI for scanning a list of file hashes on VirusTotal using their API. It allows you to input your VirusTotal API key, select a text file containing the list of file hashes, and perform the scan. The scan results are displayed in the UI and saved to a CSV file for further analysis.

Author: Bahram Dinyarian
Contact: bahramdinyarian@gmail.com

License: VirusTotal Hash Scanner - PowerShell VT API Scanner - Copyright (C) 2023  Bahram Dinyarian

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions; type `show c' for details.
#>

# Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# UI elements
$Form = New-Object System.Windows.Forms.Form
$APIKeyLabel = New-Object Windows.Forms.Label
$APIKeyTextBox = New-Object Windows.Forms.TextBox
$HashListLabel = New-Object Windows.Forms.Label
$HashListTextBox = New-Object Windows.Forms.TextBox
$HashListBrowseButton = New-Object Windows.Forms.Button
$ScanButton = New-Object Windows.Forms.Button
$LogTextBox = New-Object Windows.Forms.TextBox
$DelayLabel = New-Object Windows.Forms.Label
$DelayNumericUpDown = New-Object Windows.Forms.NumericUpDown
$VirusTotalLogoUrl = "https://www.virustotal.com/gui/images/favicon.png"

# Main UI
$Form | ForEach-Object {
    $_.Size = New-Object Drawing.Size(600, 400)
    $_.StartPosition = "CenterScreen"
    $_.Text = "VirusTotal Hash Scanner"
    $_.Controls.AddRange(@($APIKeyLabel, $APIKeyTextBox, $HashListLabel, $HashListTextBox, $HashListBrowseButton, $ScanButton, $LogTextBox, $DelayLabel, $DelayNumericUpDown))
}

# API Label
$APIKeyLabel | ForEach-Object {
    $_.Location = New-Object Drawing.Point(10, 10)
    $_.AutoSize = $true
    $_.Text = "VirusTotal API Key:"
}

# API KEY
$APIKeyTextBox | ForEach-Object {
    $_.Location = New-Object Drawing.Point(150, 10)
    $_.Width = 400
}

# Hash Label
$HashListLabel | ForEach-Object {
    $_.Location = New-Object Drawing.Point(10, 40)
    $_.AutoSize = $true
    $_.Text = "Hash List File Path:"
}

# Hash Path
$HashListTextBox | ForEach-Object {
    $_.Location = New-Object Drawing.Point(150, 40)
    $_.Width = 300
}

# Browse Button
$HashListBrowseButton | ForEach-Object {
    $_.Location = New-Object Drawing.Point(470, 40)
    $_.Text = "Browse"
    $_.Add_Click({ BrowseFile })
}

# Treshold Label
$DelayLabel | ForEach-Object {
    $_.Location = New-Object Drawing.Point(420, 75)
    $_.AutoSize = $true
    $_.Text = "Threshold:"
}

# Treshold Field
$DelayNumericUpDown | ForEach-Object {
    $_.Location = New-Object Drawing.Point(480, 73)
    $_.Width = 50
    $_.Height = 25
    $_.Minimum = 0
    $_.Maximum = 60
    $_.Value = 5
}

# Log Box
$LogTextBox | ForEach-Object {
    $_.Location = New-Object Drawing.Point(1, 110)
    $_.Width = 578
    $_.Height = 240
    $_.ScrollBars = "Vertical"
    $_.Multiline = $true
    $_.ReadOnly = $true
}

# Scan Button
{
	$ScanButton.Location = New-Object System.Drawing.Point(50,70)
	$ScanButton.Size = New-Object System.Drawing.Size(350,30)
	$ScanButton.Text = "Run VirusTotal Scan"
	$ScanButton.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
	$ScanButton.BackColor = [System.Drawing.Color]::LightGreen
	$ScanButton.ForeColor = [System.Drawing.Color]::Black
	$ScanButton.Add_MouseEnter({$ScanButton.BackColor = [System.Drawing.Color]::Green})
	$ScanButton.Add_MouseLeave({$ScanButton.BackColor = [System.Drawing.Color]::LightGreen})
	$ScanButton.Add_Click({ValidateAndScanFiles -APIKey $APIKeyTextBox.Text -HashListFilePath $HashListTextBox.Text -SecondsThreshold $DelayNumericUpDown.Value})
	$Form.Controls.Add($ScanButton)
}.Invoke()

# Log Panel Format
Function Update-FormattedLogPanel {
    param (
		[string]$hash,
        [string]$VerboseMsg,
        [int]$Total,
        [int]$Positives
		)
		
    $LogTextBox.AppendText("$hash`r`n")
    $LogTextBox.AppendText("Verbose Message:	$VerboseMsg`r`n")
    $LogTextBox.AppendText("Total AVs:	$Total`r`n")
    $LogTextBox.AppendText("Positive Detections:	$Positives`r`n")
    $LogTextBox.AppendText("`r`n")
}

# Log Panel Update
Function Update-LogPanel {
    param (
		[string]$VerboseMsg
		)
		
    if ($VerboseMsg -match 'Scan finished, information embedded') {
        Update-FormattedLogPanel -hash $hash -VerboseMsg $VerboseMsg -Total $Total -Positives $Positives
    } else {
        $LogTextBox.AppendText("$VerboseMsg`r`n")
    }
}

# Get Hash File
Function BrowseFile {
    $fileDialog = New-Object Windows.Forms.OpenFileDialog
    $fileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    $fileDialog.CheckFileExists = $true
	
    if ($fileDialog.ShowDialog() -eq "OK") {
        $fileToScan = $fileDialog.FileName
        $HashListTextBox.Text = $fileToScan
    }
}

# Read Hash File
Function Get-HashListFromFile {
    param(
		[string]$FilePath
		)	
		
    if (Test-Path $FilePath) {
        Get-Content $FilePath
    } else {
        Update-LogPanel "Hash list file not found: $FilePath"
    }
}

# Validation
Function ValidateAndScanFiles {
    $APIKey = $APIKeyTextBox.Text
    $HashListFilePath = $HashListTextBox.Text
    $SecondsThreshold = $DelayNumericUpDown.Value
	
    if (-not [string]::IsNullOrEmpty($APIKey) -and -not [string]::IsNullOrEmpty($HashListFilePath) -and (Test-Path $HashListFilePath)) {
        ScanFiles -APIKey $APIKey -HashListFilePath $HashListFilePath -SecondsThreshold $SecondsThreshold
    } else {
        Update-LogPanel "Please provide a valid API Key and Hash List file path."
    }
}

# Scan Job
Function ScanFiles {
    param(
        [Parameter(Mandatory=$true)]
        [string] $APIKey,
        [Parameter(Mandatory=$true)]
        [string] $HashListFilePath,
        [Parameter(Mandatory=$true)]
        [int] $SecondsThreshold
    )
	
	$ScanButton.Text = "Running VirusTotal Scan"
	$ScanButton.BackColor = [System.Drawing.Color]::Red
    $ScanButton.Enabled = $false
    $HashListBrowseButton.Enabled = $true
    $APIKeyTextBox.Enabled = $false
    $HashListTextBox.Enabled = $false
    $hashList = Get-HashListFromFile $HashListFilePath
	
    if ($hashList) {
        $scanResults = @()
        foreach ($hash in $hashList) {
            if ($cancelScan) { break }
            $result = Get-VTScanResults -APIKey $APIKey -Hash $hash
            if ($result) { $scanResults += $result }
            if ($pauseScan) {
                while ($pauseScan) { Start-Sleep 1 }
            }
            Start-Sleep $SecondsThreshold
        }
		
        $csvData = ConvertScanResultsToCsvString $scanResults
        $csvFilePath = "ScanResults.csv"
        $csvData | Out-File -FilePath $csvFilePath -Encoding UTF8
        $LogTextBox.AppendText("`r`n")
        Update-LogPanel "All scan results have been saved to '$csvFilePath'."
		$ScanButton.Text = "Run VirusTotal Scan"
		$ScanButton.BackColor = [System.Drawing.Color]::LightGreen
        $ScanButton.Enabled = $true
        $HashListBrowseButton.Enabled = $true
        $APIKeyTextBox.Enabled = $true
        $HashListTextBox.Enabled = $true
    }
}

# VirusTotal API
Function Get-VTScanResults {
    param (
        [string]$APIKey,
        [string]$Hash
    )
	
    $Url = "https://www.virustotal.com/vtapi/v2/file/report"
    $Headers = @{"x-apikey" = $APIKey}
    $Body = @{resource = $Hash; apikey = $APIKey}
	
    try {
        $response = Invoke-RestMethod -Method 'POST' -Uri $Url -Headers $Headers -Body $Body -ErrorAction Stop
        $verboseMsg = $response.verbose_msg
        $total = $response.total
        $positives = $response.positives
        Update-LogPanel -VerboseMsg $verboseMsg -Total $total -Positives $positives
        if (!$response.Scans) {
            Update-LogPanel "$Hash"
            $LogTextBox.AppendText("`r`n")
            return $null
        }
		
        return ConvertScansToCustomObjects -Scans $response.Scans -Hash $Hash
    } catch {
        $errorMessage = if ($_.Exception.Response.StatusCode -eq 404) {
							"File '$Hash' not found on VirusTotal."
								} else {
							"Error occurred while scanning the hash '$Hash': $_"
								}
		Update-LogPanel $errorMessage
			return $null
		}
}

# Process Objects
Function ConvertScansToCustomObjects {
    param (
        [object]$Scans,
        [string]$Hash
    )
	
    $result = @()
    foreach ($engine in $Scans.PSObject.Properties.Name) {
        $scan = $Scans.$engine
        $result += [PSCustomObject]@{
            Engine = $engine
            Detected = $scan.Detected
            Version = $scan.Version
            Detection = $scan.Result
            Updated = $scan.Update
            Hash = $Hash
        }
    }
	
    return $result
}

# Process CSV
Function ConvertScanResultsToCsvString {
    param (
		[array]$Data
		)
		
    $csvData = "Engine,Detected,Version,Detection,Updated,Hash"
    foreach ($row in $Data) {
        $csvData += "`r`n$($row.Engine),$($row.Detected),$($row.Version),$($row.Detection),$($row.Updated),$($row.Hash)"
    }
	
    return $csvData
}

# Logo
Function Set-FormIcon {
    param(
        [Parameter(Mandatory=$true)]
        [string] $LogoUrl
    )
	
    try {
        $wc = New-Object System.Net.WebClient
        $logoBytes = $wc.DownloadData($LogoUrl)
        $logoStream = New-Object System.IO.MemoryStream
        $logoStream.Write($logoBytes, 0, $logoBytes.Length)
        $logoImage = [System.Drawing.Image]::FromStream($logoStream)
        $icon = [System.Drawing.Icon]::FromHandle($logoImage.GetHicon())
        $Form.Icon = $icon
        $logoStream.Dispose()
        $wc.Dispose()
		
    } catch {
        $errorMessage = "Error loading the logo from the URL: $_"
        Update-LogPanel $errorMessage
    }
}

# Load the form icon
Set-FormIcon -LogoUrl $VirusTotalLogoUrl

# Show the form
[void]$Form.ShowDialog()
