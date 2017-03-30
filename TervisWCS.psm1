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

$WCSDSNTemplate = [PSCustomObject][Ordered]@{
    Name = "Tervis"
    PasswordID = 3459
},
[PSCustomObject][Ordered]@{
    Name = "tervisBartender"
    PasswordID = 3718
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

        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $ODBCDSNTemplate = Get-WCSODBCDSNTemplate -Name $ODBCDSNTemplateName

        $DSNName = $ODBCDSNTemplate.Name
        $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $ODBCDSNTemplate.PasswordID
        $DatabaseName = $SybaseDatabaseEntryDetails.DatabaseName

        $PropertyValue = @"
ServerName=$($SybaseDatabaseEntryDetails.ServerName)
Integrated=NO
Host=$($SybaseDatabaseEntryDetails.Host)
DatabaseName=$DatabaseName
"@ -split "`r`n"
    }

    process { 
        $ComputerNameParameter = $PSBoundParameters | ConvertFrom-PSBoundParameters | Select ComputerName | ConvertTo-HashTable
        $CIMSession = New-CimSession @ComputerNameParameter
       
        $ODBCDSN32Bit = Get-OdbcDsn -CimSession $CIMSession -Platform '32-bit' -Name $DSNName -ErrorAction SilentlyContinue
        if (-not $ODBCDSN32Bit) {
            Invoke-Command @ComputerNameParameter -ScriptBlock {
                Add-OdbcDsn -Name $Using:DSNName -DriverName "SQL Anywhere 12" -SetPropertyValue $Using:PropertyValue -Platform 32-bit -DsnType System
                New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\$Using:DSNName -PropertyType String -Name UID -Value $Using:SybaseDatabaseEntryDetails.UserName | Out-Null
                New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\$Using:DSNName -PropertyType String -Name PWD -Value $Using:SybaseDatabaseEntryDetails.Password | Out-Null
            }
        }

        $ODBCDSN64Bit = Get-OdbcDsn -CimSession $CIMSession -Platform '64-bit' -Name $DSNName -ErrorAction SilentlyContinue
        if (-not $ODBCDSN64Bit) {
            Invoke-Command @ComputerNameParameter -ScriptBlock {
                Add-OdbcDsn -Name $Using:DSNName -DriverName "SQL Anywhere 12" -SetPropertyValue $Using:PropertyValue -Platform '64-bit' -DsnType System
                New-ItemProperty -Path HKLM:\SOFTWARE\ODBC\ODBC.INI\$Using:DSNName -PropertyType String -Name UID -Value $Using:SybaseDatabaseEntryDetails.UserName | Out-Null
                New-ItemProperty -Path HKLM:\SOFTWARE\ODBC\ODBC.INI\$Using:DSNName -PropertyType String -Name PWD -Value $Using:SybaseDatabaseEntryDetails.Password | Out-Null
            }
        }
        $CIMSession | Remove-CimSession
    }
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
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    $Parameters = $PSBoundParameters

    Install-ZDesignerDriverForWindows10AndLaterFromWindowsUpdate @Parameters
    Add-PrinterDriver -Name "ZDesigner 110Xi4 203 dpi" @Parameters    

    if (-not (Test-WCSPrintersForBartenderCommanderInstalled @Parameters)) {
        Get-WCSEquipmentBottomLabelPrintEngine |
        Add-LocalWCSPrinter @Parameters
    }

    if (-not (Test-WCSPrintersForBartenderCommanderInstalled @Parameters)) {
        Throw "Couldn't install some printers or ports. To identify the missing  run Test-WCSPrintersForBartenderCommanderInstalled -verbose $ComputerName"
    }
}

function Test-WCSPrintersForBartenderCommanderInstalled {
    [CMDLetBinding()]
    param (
        $ComputerName
    )
    $Parameters = $PSBoundParameters

    $Equipment = Get-WCSEquipmentBottomLabelPrintEngine
    $PrinterPorts = Get-PrinterPort @Parameters
    $Printers = Get-Printer @Parameters

    $MissingPorts = Compare-Object -ReferenceObject ($Equipment.HostID | sort -Unique) -DifferenceObject $PrinterPorts.Name | 
    where SideIndicator -EQ "<="
    $MissingPorts | Write-VerboseAdvanced -Verbose:($VerbosePreference -ne "SilentlyContinue")

    $MissingPrinters = Compare-Object -ReferenceObject $Equipment.ID -DifferenceObject $Printers.Name | 
    where SideIndicator -EQ "<="
    $MissingPrinters | Write-VerboseAdvanced -Verbose:($VerbosePreference -ne "SilentlyContinue")

    -not $MissingPorts -or -not $MissingPrinters
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
            Add-PrinterPort -Name $HostID -PrinterHostAddress $HostID -ComputerName $ComputerName -ErrorAction SilentlyContinue
            Add-Printer -PortName $HostID -Name $ID -DriverName "ZDesigner 110Xi4 203 dpi" -ComputerName $ComputerName -ErrorAction SilentlyContinue
        } else {
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

function Get-WCSDatabaseName {
    $ConnectionString = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID 3718 | ConvertTo-SQLAnywhereConnectionString
    Get-DatabaseNames -ConnectionString $ConnectionString
}

function Invoke-TervisShippingComputersFlushDNS {
    param()
    $ShippingPCs = Get-ADComputer -Filter {Name -like "SHIP*PC"}

    Start-ParallelWork -Parameters $ShippingPCs.Name -ScriptBlock {
        param ($parameter)
        Invoke-Command -ComputerName $parameter -ScriptBlock {
            ipconfig /flushdns        
        }
    }
}