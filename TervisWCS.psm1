$EnvironmentState = [PSCustomObject][Ordered]@{
    EnvironmentName = "Production"
    SybaseTervisUserPasswordEntryGUID = "185d9c8a-531f-4fe4-9b82-b4cca1e8847f"
    SybaseQCUserPasswordEntryGUID = "6ef84c66-8e50-4e0e-92db-50eae27f8406"
    SybaseBartenderUserPasswordEntryGUID = "8f277385-c577-4dfc-94a4-eb16f1207283"
},
[PSCustomObject][Ordered]@{
    EnvironmentName = "Epsilon"
    SybaseTervisUserPasswordEntryGUID = "79f70a7f-3317-4c67-af1c-02585c4be99e"
    SybaseQCUserPasswordEntryGUID = "0f817323-3c0a-48bc-bdce-b12a32bf9bf7"
    SybaseBartenderUserPasswordEntryGUID = "dd0e83b8-823a-4446-b1b3-80686acab03c"
},
[PSCustomObject][Ordered]@{
    EnvironmentName = "Delta"
    SybaseTervisUserPasswordEntryGUID = "1e99e5b0-35ad-4d3e-8c77-e65d17529c69"
    SybaseQCUserPasswordEntryGUID = "bbbd810f-78e1-427f-a0a6-30982e93639b"
    SybaseBartenderUserPasswordEntryGUID = "b66b273d-dd3d-40a3-9c38-317ae434ed48"
}

function Get-WCSEnvironmentState {
    param (
        [Parameter(Mandatory)]$EnvironmentName
    )
    $Script:EnvironmentState | where EnvironmentName -eq $EnvironmentName
}

$WCSDSNTemplate = [PSCustomObject][Ordered]@{
    Name = "Tervis"
    EnvironmentStatePropertyContainingPasswordGUID = "SybaseTervisUserPasswordEntryGUID"
},
[PSCustomObject][Ordered]@{
    Name = "tervisBartender"
    EnvironmentStatePropertyContainingPasswordGUID = "SybaseBartenderUserPasswordEntryGUID"
}

function Get-WCSODBCDSNTemplate {
    param (
        $Name
    )
    $WCSDSNTemplate | where Name -EQ $Name
}

function Add-WCSODBCDSN {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("Tervis","tervisBartender")]
        $ODBCDSNTemplateName,

        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName,
        $DriverName = "SQL Anywhere 12"
    )
    begin {
        $ODBCDSNTemplate = Get-WCSODBCDSNTemplate -Name $ODBCDSNTemplateName
        $DSNName = $ODBCDSNTemplate.Name
    }
    process {
        $WCSEnvironmentState = Get-WCSEnvironmentState -EnvironmentName $EnvironmentName

        $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -GUID $WCSEnvironmentState.$($ODBCDSNTemplate.EnvironmentStatePropertyContainingPasswordGUID)
        $DatabaseName = $SybaseDatabaseEntryDetails.DatabaseName

        $PropertyValue = @"
ServerName=$($SybaseDatabaseEntryDetails.ServerName)
Integrated=NO
Host=$($SybaseDatabaseEntryDetails.Host)
DatabaseName=$DatabaseName
"@ -split "`r`n"

        $ComputerNameParameter = $PSBoundParameters | ConvertFrom-PSBoundParameters -Property ComputerName -AsHashTable
        $CIMSession = New-CimSession @ComputerNameParameter
       
        $ODBCDSN32Bit = Get-OdbcDsn -CimSession $CIMSession -Platform '32-bit' -Name $DSNName -ErrorAction SilentlyContinue
        if (-not $ODBCDSN32Bit) {
            Invoke-Command @ComputerNameParameter -ScriptBlock {
                Add-OdbcDsn -Name $Using:DSNName -DriverName $Using:DriverName -SetPropertyValue $Using:PropertyValue -Platform '32-bit' -DsnType System
                New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\$Using:DSNName -PropertyType String -Name UID -Value $Using:SybaseDatabaseEntryDetails.UserName | Out-Null
                New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\$Using:DSNName -PropertyType String -Name PWD -Value $Using:SybaseDatabaseEntryDetails.Password | Out-Null
            }
        }

        $ODBCDSN64Bit = Get-OdbcDsn -CimSession $CIMSession -Platform '64-bit' -Name $DSNName -ErrorAction SilentlyContinue
        if (-not $ODBCDSN64Bit) {
            Invoke-Command @ComputerNameParameter -ScriptBlock {
                Add-OdbcDsn -Name $Using:DSNName -DriverName $Using:DriverName -SetPropertyValue $Using:PropertyValue -Platform '64-bit' -DsnType System
                New-ItemProperty -Path HKLM:\SOFTWARE\ODBC\ODBC.INI\$Using:DSNName -PropertyType String -Name UID -Value $Using:SybaseDatabaseEntryDetails.UserName | Out-Null
                New-ItemProperty -Path HKLM:\SOFTWARE\ODBC\ODBC.INI\$Using:DSNName -PropertyType String -Name PWD -Value $Using:SybaseDatabaseEntryDetails.Password | Out-Null
            }
        }
        $CIMSession | Remove-CimSession
    }
}

function Remove-WCSODBCDSN {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("Tervis","tervisBartender")]
        $ODBCDSNTemplateName,

        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $DSNName = $ODBCDSNTemplateName
    }
    process {
        $ComputerNameParameter = $PSBoundParameters | ConvertFrom-PSBoundParameters | Select ComputerName | ConvertTo-HashTable
        $CIMSession = New-CimSession @ComputerNameParameter       
        Remove-OdbcDsn -Name $DSNName -Platform All -CimSession $CIMSession -DsnType All -ErrorAction SilentlyContinue
    }
}

function Update-WCSODBCDSN {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("Tervis","tervisBartender")]
        $ODBCDSNTemplateName,

        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName,
        $DriverName = "SQL Anywhere 12"
    )
    process {
        Remove-WCSODBCDSN -ODBCDSNTemplateName $ODBCDSNTemplateName -ComputerName $ComputerName
        Add-WCSODBCDSN -ODBCDSNTemplateName $ODBCDSNTemplateName -ComputerName $ComputerName -EnvironmentName $EnvironmentName -DriverName $DriverName
    }
}

function Install-ZDesignerDriverForWindows10AndLaterFromWindowsUpdate {
    param (
        $ComputerName
    )
    Invoke-Command -ScriptBlock {
        $ZebraDriver = get-windowsdriver -Online | 
        where providername -eq zebra |
        where ClassName -eq Printer |
        where Version -eq 5.1.7.6290

        if (-not $ZebraDriver) {
            Invoke-WebRequest http://download.windowsupdate.com/c/msdownload/update/driver/drvs/2016/06/20857735_abfb8f058ce8dd7bbb70ec4a7df3947f81b204a8.cab -OutFile $env:TEMP\ZDesigner.cab
            New-Item -Path $env:TEMP\zdesigner -ItemType Directory
            expand.exe -F:* $env:TEMP\zdesigner.cab $env:TEMP\zdesigner
            pnputil.exe -i -a $env:TEMP\zdesigner\ZBRN.inf
        }
    } @PSBoundParameters
}

function Install-WCSPrinters {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Parameter(Mandatory)][ValidateSet("Top","Bottom")]$PrintEngineOrientationRelativeToLabel
    )
    process {
        Install-ZDesignerDriverForWindows10AndLaterFromWindowsUpdate -ComputerName $ComputerName
        Add-PrinterDriver -Name "ZDesigner 110Xi4 203 dpi" -ComputerName $ComputerName

        if (-not (Test-WCSPrintersInstalled @PSBoundParameters)) {
            Get-WCSEquipment -EnvironmentName $EnvironmentName -PrintEngineOrientationRelativeToLabel $PrintEngineOrientationRelativeToLabel |
            Add-LocalWCSPrinter -ComputerName $ComputerName
        }

        if (-not (Test-WCSPrintersInstalled @PSBoundParameters)) {
            Throw "Couldn't install some printers or ports. To identify the missing  run Test-WCSPrintersInstalled -Verbose -ComputerName $ComputerName -PrintEngineOrientationRelativeToLabel $PrintEngineOrientationRelativeToLabel -EnvironmentName $EnvironmentName"
        }
    }
}

function Update-WCSPrinters {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Parameter(Mandatory)][ValidateSet("Top","Bottom")]$PrintEngineOrientationRelativeToLabel
    )
    process {
        Get-WCSEquipment -EnvironmentName $EnvironmentName -PrintEngineOrientationRelativeToLabel $PrintEngineOrientationRelativeToLabel |
        Add-LocalWCSPrinter -ComputerName $ComputerName -Force
    }
}

function Test-WCSPrintersInstalled {
    [CMDLetBinding()]
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$EnvironmentName,
        [Parameter(Mandatory)][ValidateSet("Top","Bottom")]$PrintEngineOrientationRelativeToLabel
    )
    $Equipment = Get-WCSEquipment -EnvironmentName $EnvironmentName -PrintEngineOrientationRelativeToLabel $PrintEngineOrientationRelativeToLabel
    $PrinterPorts = Get-PrinterPort -ComputerName $ComputerName
    $Printers = Get-Printer -ComputerName $ComputerName

    $MissingPorts = Compare-Object -ReferenceObject ($Equipment.HostID | sort -Unique) -DifferenceObject $PrinterPorts.Name | 
    where SideIndicator -EQ "<="
    $MissingPorts | Write-VerboseAdvanced -Verbose:($VerbosePreference -ne "SilentlyContinue")

    $MissingPrinters = Compare-Object -ReferenceObject $Equipment.ID -DifferenceObject $Printers.Name | 
    where SideIndicator -EQ "<="
    $MissingPrinters | Write-VerboseAdvanced -Verbose:($VerbosePreference -ne "SilentlyContinue")

    -not $MissingPorts -and -not $MissingPrinters
}

function Add-LocalWCSPrinter {
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$ID,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$HostID,
        $ComputerName,
        [Switch]$Force
    )
    process {
        if ($ComputerName) {
            if ($Force) {
                Remove-Printer -Name $ID -ComputerName $ComputerName -ErrorAction SilentlyContinue
                Remove-PrinterPort -Name $HostID -ComputerName $ComputerName -ErrorAction SilentlyContinue
            }
            Add-PrinterPort -Name $HostID -PrinterHostAddress $HostID -ComputerName $ComputerName -ErrorAction SilentlyContinue
            Add-Printer -PortName $HostID -Name $ID -DriverName "ZDesigner 110Xi4 203 dpi" -ComputerName $ComputerName -ErrorAction SilentlyContinue
        } else {
            if ($Force) {
                Remove-Printer -Name $ID -ErrorAction SilentlyContinue
                Remove-PrinterPort -Name $HostID -ErrorAction SilentlyContinue
            }
            Add-PrinterPort -Name $HostID -PrinterHostAddress $HostID -ErrorAction SilentlyContinue
            Add-Printer -PortName $HostID -Name $ID -DriverName "ZDesigner 110Xi4 203 dpi" -ErrorAction SilentlyContinue
        }
    }
}

function Remove-LocalWCSPrinter {
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$ID,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$HostID,
        $ComputerName
    )
    begin {
        $ComputerNameParameter = $PSBoundParameters | 
        ConvertFrom-PSBoundParameters | 
        where ComputerName
    }
    process {
        if ($ComputerName) {
            Remove-Printer -Name $ID -ComputerName $ComputerName 
            Remove-PrinterPort -Name $HostID -ComputerName $ComputerNameet
        } else {
            Remove-Printer -Name $ID
            Remove-PrinterPort -Name $HostID
        }
    }
}

function Invoke-TervisShippingComputersFlushDNS {
    param()
    $ShippingPCs = Get-ADComputer -Filter {Name -like "SHIP*PC"}

    Start-ParallelWork -Parameters $ShippingPCs.Name -ScriptBlock {
        param ($parameter)
        $ConnectionStatus = Test-NetConnection -ComputerName $parameter -CommonTCPPort WINRM -WarningAction SilentlyContinue
        if ($ConnectionStatus.TcpTestSucceeded) {
            Invoke-Command -ComputerName $parameter -ScriptBlock {
                ipconfig /flushdns
            }       
        } else {
            Write-Warning "Could not connect to $parameter"
        }
    }
}

function Invoke-GPUpdateOnAllShipStations {
    $Computers = Get-ADComputer -Filter {name -like "ship*"} | select -ExpandProperty Name
#    Start-ParallelWork -Parameters $Computers -ScriptBlock {
#        Invoke-Command -ComputerName $Parameter -ScriptBlock {
#            gpupdate
#            $env:COMPUTERNAME
#        }
#    }
    foreach ($Computer in $Computers) {        
        Invoke-Command -ComputerName $Computer -ScriptBlock {
            gpupdate
            $env:COMPUTERNAME
        }
    }
}

function Test-WCSShortcutLink {
    $Computers = Get-ADComputer -Filter {name -like "ship*"} | select -ExpandProperty Name
    $LocalPath = "C:\users\Public\Desktop\WCS (PRD-WCSApp01).lnk"
        foreach ($Computer in $Computers) {        
            $Result = Test-Path -Path ($LocalPath | ConvertTo-RemotePath -ComputerName $Computer)
            [PSCustomObject][Ordered]@{
                ComputerName = $Computer
                ShortcutExists = $Result
            }
        }
}

function Resolve-WCSCnameToHostname {
    param (
        [Parameter(Mandatory)]$Name
    )
    $Response = Resolve-DnsName -Name $Name -Type CNAME
    $Response.NameHost -replace ".tervis.prv", ""
}

function Invoke-PostWCSSybaseDatabaseRefreshSybaseSteps {    
    $OldComputerName = Resolve-WCSCnameToHostname -Name WCSJavaApplication.Production.Tervis.prv

    foreach ($EnvironmentName in "Delta","Epsilon") {
        Set-WCSSystemParameterCS_ServerBasedOnNode -EnvironmentName $EnvironmentName
        $ComputerName = Resolve-WCSCnameToHostname -Name "WCSJavaApplication.$EnvironmentName.Tervis.prv"
        Update-TervisWCSReferencesToComputerName -ComputerName $ComputerName -OldComputerName $OldComputerName -EnvironmentName $EnvironmentName    
    }
}


function Invoke-PostWCSSybaseDatabaseRefresh {
    $Nodes = Get-TervisApplicationNode -ApplicationName Progistics -EnvironmentName Delta, Epsilon
    $Nodes | Set-ProgisticsMSNToHigherThanWCSSybaseConnectShipMSNPreviouslyUsed

    Invoke-PostWCSSybaseDatabaseRefreshSybaseSteps
}

function Get-PostWCSSybaseDatabaseRefreshChanges {
    foreach ($EnvironmentName in "Delta","Epsilon") {
        Get-TervisWCSSystemParameterCS_Server -EnvironmentName $EnvironmentName
        Get-TervisWCSTervisContentsLabelsAndTervisSalesChannelXRefFileName -EnvironmentName $EnvironmentName
    }
}

function Set-ShipStationTwinPrint {
    param (
        $TopPrintEngine,
        $BottomPrintEngine,
        $ShipStationNumber
    )
    Read-Host "Update printers in WCS java application"
    $WCSEquipment = Get-WCSEquipment -EnvironmentName Production

    $WCSEquipment | Where-Object { $_.ID -eq "Shipping$ShipStationNumber" -or $_.ID -eq "Shipping_PL$ShipStationNumber" }
    
    Update-WCSPrinters -ComputerName wcsjavaapplication.production.tervis.prv -EnvironmentName Production -PrintEngineOrientationRelativeToLabel Top
    Update-WCSPrinters -ComputerName wcsjavaapplication.production.tervis.prv -EnvironmentName Production -PrintEngineOrientationRelativeToLabel Bottom
    Update-WCSPrinters -ComputerName BartenderCommander.production.tervis.prv -EnvironmentName Production -PrintEngineOrientationRelativeToLabel Top
    Update-WCSPrinters -ComputerName BartenderCommander.production.tervis.prv -EnvironmentName Production -PrintEngineOrientationRelativeToLabel Bottom

    Read-Host "Restart labelmgrship and labelmgrpack system processes within WCS"
}

function Restart-WCSSystemServers {
    param (
        [switch]$IncludeSybaseServer
    )

    Send-TervisMailMessage -To ShippingIssues@tervis.com -Subject "WCS System Rebooting" -From HelpDeskTeam@tervis.com -Body @"
Team,

$(if ($IncludeSybaseServer){"P-WCS, "})PRD-WCSApp01, PRD-Bartender01, and PRD-Progis01 are currently being rebooted.

Thanks,

IT
"@
    if ($IncludeSybaseServer) {
        Restart-Computer -ComputerName "P-WCS" -Wait -Force
        Write-Warning "The Sybase server has been restarted. Please check SOA processes to make sure they are still running."
    }

    Start-ParallelWork -Parameters "PRD-WCSApp01","PRD-Bartender01","PRD-Progis01" -ScriptBlock {
        param($ComputerName)
        Restart-Computer -Wait -ComputerName $ComputerName -Force
    } 

    Send-TervisMailMessage -To ShippingIssues@tervis.com -Subject "RE: WCS System Rebooting" -From HelpDeskTeam@tervis.com -Body @"
Team,

The reboot of $(if ($IncludeSybaseServer){"P-WCS, "})PRD-WCSApp01, PRD-Bartender01, and PRD-Progis01 has completed.

Thanks,

IT
"@
}

function Install-TervisWCSSystemScheduledReboot {
    New-ADServiceAccount -
    $Nodes = Get-WCSSystemNodes -EnvironmentName Production
    $WCSSystemADComputers = $Nodes.ComputerName | Get-ADComputer
    $ADDomain = Get-ADDomain
    $GroupManagedServiceAccountName = "PRD-WCSSystem"

    New-ADServiceAccount -Name $GroupManagedServiceAccountName -DNSHostName "$GroupManagedServiceAccountName$($ADDomain.DNSRoot)"-PrincipalsAllowedToRetrieveManagedPassword $WCSSystemADComputers
    Test-ADServiceAccount -Identity $GroupManagedServiceAccountName

    Install-PowerShellApplicationScheduledTask -FunctionName Restart-WCSSystemServers -RepetitionIntervalName EveryDayAt7am3pm11pm
}

function Get-WCSSystemNodes {
    param (
        [String]$EnvironmentName
    )
    Get-TervisApplicationNode -ApplicationName Progistics,WCSJavaApplication,BartenderCommander -EnvironmentName $EnvironmentName
}

function Get-FedexSMCorruptedDataDownloads {
    param(
        [parameter(Mandatory)]$Computername
    )
    Get-ChildItem -Path "\\$Computername\C$\FedEx\FedEx_Comm\SasvDataDnld\*jar.jar*"
}

function Get-FedexSMHourlyUploads {
    param(
        [parameter(Mandatory)]$Computername
    )
    Get-ChildItem -Path "\\$Computername\C$\FedEx\FedEx_Admn\hourlyupload\*.HUP"
}
