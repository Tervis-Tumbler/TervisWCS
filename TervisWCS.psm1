function Get-ConveyorScaleNumberOfUniqueWeights {
    param (
        [Parameter(Mandatory)]$NumberOfBoxesToSample
    )
    $Query = @"
SELECT top $NumberOfBoxesToSample
    ts,
    weight
FROM "qc"."ScaleLog"
order by ts DESC 
"@

    $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID 3459
    $ConnectionString = $SybaseDatabaseEntryDetails | ConvertTo-SQLAnywhereConnectionString

    $Results = Invoke-SQLAnywhereSQL -ConnectionString $ConnectionString -SQLCommand $Query -DatabaseEngineClassMapName SQLAnywhere -ConvertFromDataRow

    $ConveyorScaleNumberOfUniqueWeights = $Results | 
    Group-Object -Property Weight | 
    Measure-Object | 
    Select-Object -ExpandProperty Count

    $ConveyorScaleNumberOfUniqueWeights
}

function Add-TervisWCSDSN {
    $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID 3459
    $DatabaseName = $SybaseDatabaseEntryDetails.DatabaseName

    $PropertyValue = @"
ServerName=$($SybaseDatabaseEntryDetails.ServerName)
Integrated=NO
Host=$($SybaseDatabaseEntryDetails.Host)
DatabaseName=$DatabaseName
"@ -split "`r`n"

    Add-OdbcDsn -Name Tervis -DriverName "SQL Anywhere 12" -SetPropertyValue $PropertyValue -Platform 32-bit -DsnType System
    New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\$DatabaseName -PropertyType String -Name UID -Value $Credential.UserName
    New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\$DatabaseName -PropertyType String -Name PWD -Value $Credential.GetNetworkCredential().password

    Add-OdbcDsn -Name Tervis -DriverName "SQL Anywhere 12" -SetPropertyValue $PropertyValue -Platform '64-bit' -DsnType System
    New-ItemProperty -Path HKLM:\SOFTWARE\ODBC\ODBC.INI\$DatabaseName -PropertyType String -Name UID -Value $Credential.UserName
    New-ItemProperty -Path HKLM:\SOFTWARE\ODBC\ODBC.INI\$DatabaseName -PropertyType String -Name PWD -Value $Credential.GetNetworkCredential().password
}

function Get-WCSEquipment {
    $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID 3459
    $ConnectionString = $SybaseDatabaseEntryDetails | ConvertTo-SQLAnywhereConnectionString

    $Query = @"
SELECT * FROM "qc"."Equipment"
"@
    Invoke-SQLAnywhereSQL -ConnectionString $ConnectionString -SQLCommand $Query -DatabaseEngineClassMapName SQLAnywhere -ConvertFromDataRow
}

function Get-WCSEquipmentBottomLabelPrintEngine {
    Get-WCSEquipment |
    where id -Match _PL
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

function Install-WCSPrintersForBartenderCommander {
    param (
        $ComputerName
    )
    Install-ZDesignerDriverForWindows10AndLaterFromWindowsUpdate @PSBoundParameters
    Add-PrinterDriver -Name "ZDesigner 110Xi4 203 dpi" @PSBoundParameters
    
    Get-WCSEquipmentBottomLabelPrintEngine |
    Add-LocalWCSPrinter @PSBoundParameters
}

function Add-LocalWCSPrinter {
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
            Add-PrinterPort -Name $HostID -PrinterHostAddress $HostID -ComputerName $ComputerName
            Add-Printer -PortName $HostID -Name $ID -DriverName "ZDesigner 110Xi4 203 dpi" -ComputerName $ComputerName 
        } else {
            Add-PrinterPort -Name $HostID -PrinterHostAddress $HostID 
            Add-Printer -PortName $HostID -Name $ID -DriverName "ZDesigner 110Xi4 203 dpi"
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