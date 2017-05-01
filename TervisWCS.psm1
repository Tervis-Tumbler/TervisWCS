$EnvironmentState = [PSCustomObject][Ordered]@{
    EnvironmentName = "Production"
    SybaseTervisUserPasswordEntryID = 3458
    SybaseQCUserPasswordEntryID = 3459
    SybaseBartenderUserPasswordEntryID = 3718
},
[PSCustomObject][Ordered]@{
    EnvironmentName = "Epsilon"
    SybaseTervisUserPasswordEntryID = 3457
    SybaseQCUserPasswordEntryID = 4116
    SybaseBartenderUserPasswordEntryID = 4118
},
[PSCustomObject][Ordered]@{
    EnvironmentName = "Delta"
    SybaseTervisUserPasswordEntryID = 3456
    SybaseQCUserPasswordEntryID = 4115
    SybaseBartenderUserPasswordEntryID = 4117
}

function Get-WCSEnvironmentState {
    param (
        [Parameter(Mandatory)]$EnvironmentName
    )
    $Script:EnvironmentState | where EnvironmentName -eq $EnvironmentName
}

$WCSDSNTemplate = [PSCustomObject][Ordered]@{
    Name = "Tervis"
    EnvironmentStatePropertyContainingPasswordID = "SybaseTervisUserPasswordEntryID"
},
[PSCustomObject][Ordered]@{
    Name = "tervisBartender"
    EnvironmentStatePropertyContainingPasswordID = "SybaseBartenderUserPasswordEntryID"
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
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    begin {
        $ODBCDSNTemplate = Get-WCSODBCDSNTemplate -Name $ODBCDSNTemplateName
        $DSNName = $ODBCDSNTemplate.Name
    }
    process {
        $WCSEnvironmentState = Get-WCSEnvironmentState -EnvironmentName $EnvironmentName

        $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $WCSEnvironmentState.$($ODBCDSNTemplate.EnvironmentStatePropertyContainingPasswordID)
        $DatabaseName = $SybaseDatabaseEntryDetails.DatabaseName

        $PropertyValue = @"
ServerName=$($SybaseDatabaseEntryDetails.ServerName)
Integrated=NO
Host=$($SybaseDatabaseEntryDetails.Host)
DatabaseName=$DatabaseName
"@ -split "`r`n"

        $ComputerNameParameter = $PSBoundParameters | ConvertFrom-PSBoundParameters | Select ComputerName | ConvertTo-HashTable
        $CIMSession = New-CimSession @ComputerNameParameter
       
        $ODBCDSN32Bit = Get-OdbcDsn -CimSession $CIMSession -Platform '32-bit' -Name $DSNName -ErrorAction SilentlyContinue
        if (-not $ODBCDSN32Bit) {
            Invoke-Command @ComputerNameParameter -ScriptBlock {
                Add-OdbcDsn -Name $Using:DSNName -DriverName "SQL Anywhere 12" -SetPropertyValue $Using:PropertyValue -Platform '32-bit' -DsnType System
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
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    process {
        Remove-WCSODBCDSN -ODBCDSNTemplateName $ODBCDSNTemplateName -ComputerName $ComputerName
        Add-WCSODBCDSN -ODBCDSNTemplateName $ODBCDSNTemplateName -ComputerName $ComputerName -EnvironmentName $EnvironmentName
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

    -not $MissingPorts -or -not $MissingPrinters
}

function Add-LocalWCSPrinter {
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$ID,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$HostID,
        $ComputerName
    )
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
