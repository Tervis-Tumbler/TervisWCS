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

function Update-TervisWCSTervisContentsLabelsAndTervisSalesChannelXRefFileName {
    param (
        [Parameter(Mandatory)]$ComputerName,
        $OldComputerName,
        [Parameter(Mandatory)]$PasswordID
    )
    $Query = @"
update TervisContentsLabels
set filename = replace(filename, '$OldComputerName', '$ComputerName');

update TervisSalesChannelXRef
set filename = replace(filename, '$OldComputerName', '$ComputerName');
"@

    $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $PasswordID
    $ConnectionString = $SybaseDatabaseEntryDetails | ConvertTo-SQLAnywhereConnectionString

    Invoke-SQLAnywhereSQL -ConnectionString $ConnectionString -SQLCommand $Query -DatabaseEngineClassMapName SQLAnywhere -ConvertFromDataRow
}

function Set-TervisWCSSystemParameterCS_Server {
    param (
        [Parameter(Mandatory)]$CS_Server,
        [Parameter(Mandatory)]$PasswordID
    )
    $Query = @"
update SystemParameters
set value = '$CS_Server'
where Name = 'CS_Server';
"@

    $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $PasswordID
    $ConnectionString = $SybaseDatabaseEntryDetails | ConvertTo-SQLAnywhereConnectionString

    Invoke-SQLAnywhereSQL -ConnectionString $ConnectionString -SQLCommand $Query -DatabaseEngineClassMapName SQLAnywhere -ConvertFromDataRow    
}

function Get-TervisWCSSystemParameterCS_Server {
    param (
        [Parameter(Mandatory)]$PasswordID
    )
    $Query = @"
select name,value from SystemParameters
where Name = 'CS_Server';
"@

    $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $PasswordID
    $ConnectionString = $SybaseDatabaseEntryDetails | ConvertTo-SQLAnywhereConnectionString

    Invoke-SQLAnywhereSQL -ConnectionString $ConnectionString -SQLCommand $Query -DatabaseEngineClassMapName SQLAnywhere -ConvertFromDataRow    
}

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
        Remove-OdbcDsn -Name tervis -Platform All -CimSession $CIMSession -DsnType All -ErrorAction SilentlyContinue
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

function Get-WCSEquipment {
    param (
        [Parameter(Mandatory)]$EnvironmentName,
        [ValidateSet("Top","Bottom")]$PrintEngineOrientation
    )
    $WCSEnvironmentState = Get-WCSEnvironmentState -EnvironmentName $EnvironmentName
    $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $WCSEnvironmentState.SybaseQCUserPasswordEntryID
    $ConnectionString = $SybaseDatabaseEntryDetails | ConvertTo-SQLAnywhereConnectionString

    $Query = @"
SELECT * FROM "qc"."Equipment"
"@
    $WCSEquipment = Invoke-SQLAnywhereSQL -ConnectionString $ConnectionString -SQLCommand $Query -DatabaseEngineClassMapName SQLAnywhere -ConvertFromDataRow

    if ($PrintEngineOrientation -eq "Top") {
        $WCSEquipment |
        where id -Match Shipping |
        where id -NotMatch _PL
    } elseif ($PrintEngineOrientation -eq "Bottom") {
        $WCSEquipment |
        where id -Match _PL
    } else {
        $WCSEquipment
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
        [Parameter(Mandatory)][ValidateSet("Top","Bottom")]$PrintEngineOrientation
    )
    process {
        Install-ZDesignerDriverForWindows10AndLaterFromWindowsUpdate -ComputerName $ComputerName
        Add-PrinterDriver -Name "ZDesigner 110Xi4 203 dpi" -ComputerName $ComputerName

        if (-not (Test-WCSPrintersInstalled @PSBoundParameters)) {
            Get-WCSEquipment -EnvironmentName $EnvironmentName -PrintEngineOrientation $PrintEngineOrientation |
            Add-LocalWCSPrinter -ComputerName $ComputerName
        }

        if (-not (Test-WCSPrintersInstalled @PSBoundParameters)) {
            Throw "Couldn't install some printers or ports. To identify the missing  run Test-WCSPrintersInstalled -Verbose -ComputerName $ComputerName -PrintEngineOrientation $PrintEngineOrientation -EnvironmentName $EnvironmentName"
        }
    }
}

function Test-WCSPrintersInstalled {
    [CMDLetBinding()]
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$EnvironmentName,
        [Parameter(Mandatory)][ValidateSet("Top","Bottom")]$PrintEngineOrientation
    )
    $Equipment = Get-WCSEquipment -EnvironmentName $EnvironmentName -PrintEngineOrientation $PrintEngineOrientation
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

function Get-WCSDatabaseName {
    $ConnectionString = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID 3718 | ConvertTo-SQLAnywhereConnectionString
    Get-DatabaseNames -ConnectionString $ConnectionString
}

function Invoke-WCSJavaApplicationProvision {
    param (
        $EnvironmentName
    )
    Invoke-ClusterApplicationProvision -ClusterApplicationName WCSJavaApplication -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName WCSJavaApplication -EnvironmentName $EnvironmentName
    $Nodes | Add-WCSODBCDSN -ODBCDSNTemplateName Tervis
    $Nodes | Set-WCSEnvironmentVariables
    $Nodes | Expand-QCSoftwareZipPackage
    $Nodes | Invoke-ProcessWCSTemplateFiles
    $Nodes | New-QCSoftwareShare
    $Nodes | Install-WCSServiceManager
    $Nodes | Start-WCSServiceManagerService
    $Nodes | New-WCSShortcut
    $Nodes | Set-WCSBackground
    $Nodes | New-WCSJavaApplicationFirewallRules
    $Nodes | Install-WCSPrinters -PrintEngineOrientation Top
}

function Set-WCSSystemParameterCS_ServerBasedOnNode {
    param (       
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    begin {
        $ADDomain = Get-ADDomain
    }
    process {
        $WCSEnvironmentState = Get-WCSEnvironmentState -EnvironmentName $EnvironmentName
        Set-TervisWCSSystemParameterCS_Server -CS_Server "Progistics.$EnvironmentName.$($ADDomain.DNSRoot)" -PasswordID $WCSEnvironmentState.SybaseQCUserPasswordEntryID
    }
}

function New-WCSJavaApplicationFirewallRules {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Switch]$Force
    )
    process {
        New-TervisFirewallRule -ComputerName $ComputerName -DisplayName "WCS Control" -Group WCS -LocalPort 26000-26100 -Name "WCSControl" -Direction Inbound -Action Allow -Protocol tcp -Force:$Force
        New-TervisFirewallRule -ComputerName $ComputerName -DisplayName "WCS RMI" -Group WCS -LocalPort 26300-26400 -Name "WCSRMI" -Direction Inbound -Action Allow -Protocol tcp -Force:$Force
    }
}

function Get-WCSJavaApplicationGitRepositoryPath {
    $ADDomain = Get-ADDomain -Current LocalComputer
    "\\$($ADDomain.DNSRoot)\applications\GitRepository\WCSJavaApplication"
}

function Start-WCSServiceManagerService {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Start-Service -Name servicemgr
        }
    }
}

function Set-WCSBackground {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    begin {
        $BackGroundSourcePath = "$(Get-WCSJavaApplicationGitRepositoryPath)\Background"
        $BackGroundPathLocal = "$(Get-WCSJavaApplicationRootDirectory)\Gif"
    }
    process {
        $BackGroundPathRemote = $BackGroundPathLocal | ConvertTo-RemotePath -ComputerName $ComputerName
        Copy-Item -Force -Path "$BackGroundSourcePath\backgroundQC.$EnvironmentName.png" -Destination $BackGroundPathRemote\backgroundQC.png
    }
}

function New-WCSShortcut {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $WCSJavaApplicationRootDirectory = Get-WCSJavaApplicationRootDirectory
    }
    process {
        $WCSShortcutPath = $WCSJavaApplicationRootDirectory | ConvertTo-RemotePath -ComputerName $ComputerName
        Set-Shortcut -LinkPath "$WCSShortcutPath\WCS ($ComputerName).lnk" -IconLocation "\\$ComputerName\QcSoftware\Gif\tfIcon.ico,0" -TargetPath "\\$ComputerName\QcSoftware\Bin\runScreens.cmd" -Arguments "-q -p \\$ComputerName\QcSoftware -n %COMPUTERNAME%"
    }
}

function New-QCSoftwareShare {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $WCSJavaApplicationRootDirectory = Get-WCSJavaApplicationRootDirectory
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if (-not (Get-SmbShare -Name QcSoftware -ErrorAction SilentlyContinue)) {
                New-SmbShare -Name QcSoftware -Path $Using:WCSJavaApplicationRootDirectory -ChangeAccess "Everyone" | Out-Null
                $ACL = Get-Acl -Path $Using:WCSJavaApplicationRootDirectory
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Modify","ContainerInherit,ObjectInherit", "None", "Allow")
                $ACL.SetAccessRule($AccessRule)
                Set-Acl -path $Using:WCSJavaApplicationRootDirectory -AclObject $Acl
            }
        }
    }  
}

function Get-WCSJavaApplicationRootDirectory {
    "C:\QcSoftware"
}

function Set-WCSEnvironmentVariables {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $WCSJavaApplicationRootDirectory = Get-WCSJavaApplicationRootDirectory

        $EnvironmentVariables = [PSCustomObject]@{
            Name = "CONFIG_DIR"
            Value = "$WCSJavaApplicationRootDirectory\config"
        },
        [PSCustomObject]@{
            Name = "JSWAT"
            Value = "$WCSJavaApplicationRootDirectory\jswat"
        },
        [PSCustomObject]@{
            Name = "JSWAT_HOME"
            Value = "$WCSJavaApplicationRootDirectory\jswat"
        },
        [PSCustomObject]@{
            Name = "PROJECT_BASE"
            Value = "$WCSJavaApplicationRootDirectory"
        }

        $PathsToAddToEnvironmentVariablePath = @(
            "$WCSJavaApplicationRootDirectory\lib",
            "$WCSJavaApplicationRootDirectory\Bin"
        )
    }
    process {
        $EnvironmentVariablesResult = $EnvironmentVariables | 
            Set-EnvironmentVariable -ComputerName $ComputerName -Target Machine -ReturnTrueIfSet
        $PathsResult = $PathsToAddToEnvironmentVariablePath | 
            Add-PathToEnvironmentVariablePath -ComputerName $ComputerName -Target Machine -ReturnTrueIfSet
        if ($EnvironmentVariablesResult -or $PathsResult) {
            Restart-Computer -ComputerName $ComputerName
            Wait-ForNodeRestart -ComputerName $ComputerName
        }
    }
}

function Set-EnvironmentVariable {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Name,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Value,
        [Parameter(Mandatory)][ValidateSet("Machine","Process","User")]$Target,
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Switch]$Force,
        [Switch]$ReturnTrueIfSet
    )
    process {
        if ($ComputerName) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                if ( -not (Get-Item -Path Env:\$Using:Name -ErrorAction SilentlyContinue) -or $Using:Force) {
                    [Environment]::SetEnvironmentVariable($Using:Name, $Using:Value, $Using:Target)
                    if ($Using:ReturnTrueIfSet) { $true }
                }
            }
        } else {
            if ( -not (Get-Item -Path Env:\$Name -ErrorAction SilentlyContinue) -or $Force) {
                [Environment]::SetEnvironmentVariable($Name, $Value, $Target)
                if ($ReturnTrueIfSet) { $true }
            }
        }
    }
}

function Add-PathToEnvironmentVariablePath {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Path,
        [Parameter(Mandatory)][ValidateSet("Machine","Process","User")]$Target,
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Switch]$ReturnTrueIfSet
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {            
            if ( -not ($env:Path -split ";" -contains $Using:Path)) {
                [Environment]::SetEnvironmentVariable("PATH", "$env:Path;$Using:Path", $Using:Target)
                if ($Using:ReturnTrueIfSet) { $true }
            }
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

function Expand-QCSoftwareZipPackage {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName        
    )
    begin {
        $ADDomain = Get-ADDomain -Current LocalComputer
        $ZipFileName = "QcSoftware.zip"
        $ZipFilePathRemote = "\\$($ADDomain.DNSRoot)\applications\GitRepository\WCSJavaApplication\$ZipFileName"
        $ZipFileCopyPathLocal = "C:\ProgramData\TervisWCS\"
        $ExtractPath = Get-WCSJavaApplicationRootDirectory        
    }
    process {
        $ZipFileCopyPathRemote = $ZipFileCopyPathLocal | ConvertTo-RemotePath -ComputerName $ComputerName
        New-Item -Force -ItemType Directory -Path $ZipFileCopyPathRemote | Out-Null
        if (-not (Test-Path $ZipFileCopyPathRemote\$ZipFileName)) {
            Copy-Item -Path $ZipFilePathRemote -Destination $ZipFileCopyPathRemote
        }
        
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if (-not (Test-Path $Using:ExtractPath)) {
                Expand-Archive -Path "$Using:ZipFileCopyPathLocal\$Using:ZipFileName" -DestinationPath $Using:ExtractPath -Force
            }
        }
    }
}

function Install-WCSServiceManager {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName        
    )
    begin {
        $RootDirectory = Get-WCSJavaApplicationRootDirectory
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-Location -Path $Using:RootDirectory\bin
            cmd /c "..\profile.bat && servicemgr -i"
            Set-Service -Name servicemgr -StartupType Automatic
        }
    }
}

function Remove-WCSServiceManager {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName        
    )
    begin {
        $RootDirectory = Get-WCSJavaApplicationRootDirectory
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-Location -Path $Using:RootDirectory\bin
            cmd /c "..\profile.bat && servicemgr -r"
        }
    }
}

function Set-WCSProfileBat {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    begin {
        $RootDirectory = Get-WCSJavaApplicationRootDirectory
        $ProfileTemplateFile = "$(Get-WCSJavaApplicationGitRepositoryPath)\Profile.bat.pstemplate"
    }
    process {
        $WCSEnvironmentState = Get-WCSEnvironmentState -EnvironmentName $EnvironmentName
        $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $WCSEnvironmentState.SybaseQCUserPasswordEntryID
        $Global:DATABASE_MACHINE = $SybaseDatabaseEntryDetails.Host
        $Global:DATABASE_NAME = $SybaseDatabaseEntryDetails.DatabaseName
        $Global:QCCS_DB_NAME = $SybaseDatabaseEntryDetails.DatabaseName
        $Global:DATABASE_PORT = $SybaseDatabaseEntryDetails.Port

        $RootDirectoryRemote = $RootDirectory | ConvertTo-RemotePath -ComputerName $ComputerName
        $Global:ComputerName = $ComputerName

        $ProfileTemplateFile | 
        Invoke-ProcessTemplateFile |
        Out-File -Encoding ascii -NoNewline "$RootDirectoryRemote\profile.bat"
    }
}

function Invoke-ProcessWCSTemplateFiles {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    begin {
        $RootDirectory = Get-WCSJavaApplicationRootDirectory
        $TemplateFilesPath = Get-WCSJavaApplicationGitRepositoryPath
    }
    process {
        $WCSEnvironmentState = Get-WCSEnvironmentState -EnvironmentName $EnvironmentName
        $SybaseDatabaseEntryDetails = Get-PasswordstateSybaseDatabaseEntryDetails -PasswordID $WCSEnvironmentState.SybaseQCUserPasswordEntryID
        $TemplateVariables = @{
            DATABASE_MACHINE = $SybaseDatabaseEntryDetails.Host
            DATABASE_NAME = $SybaseDatabaseEntryDetails.DatabaseName
            QCCS_DB_NAME = $SybaseDatabaseEntryDetails.DatabaseName
            DATABASE_PORT = $SybaseDatabaseEntryDetails.Port
            ComputerName = $ComputerName
            EnvironmentName = $EnvironmentName
        }

        $RootDirectoryRemote = $RootDirectory | ConvertTo-RemotePath -ComputerName $ComputerName
        Invoke-ProcessTemplatePath -Path $TemplateFilesPath -DestinationPath $RootDirectoryRemote -TemplateVariables $TemplateVariables
    }
}

function ConvertFrom-StringUsingRegexCaptureGroup {
    param (
        [Regex]$Regex,
        [Parameter(ValueFromPipeline)]$Content
    )
    process {
        $Match = $Regex.Match($Content)
        $Object = [pscustomobject]@{} 
        
        foreach ($GroupName in $Regex.GetGroupNames() | select -Skip 1) {
            $Object | 
            Add-Member -MemberType NoteProperty -Name $GroupName -Value $Match.Groups[$GroupName].Value 
        }
        $Object
    }
}

function Get-WCSLogFileTail {
    param (
        $ComputerName,
        $Tail = 100
    )
    $WCSJavaApplicationRootDirectoryRemote = Get-WCSJavaApplicationRootDirectory | ConvertTo-RemotePath -ComputerName $ComputerName
    $LogFilePath = "$WCSJavaApplicationRootDirectoryRemote\log\tmp"
    $LogFiles = Get-ChildItem -Path $LogFilePath -File | where name -NotMatch ".lnk"
    $LogFiles | ForEach-Object { 
        $_.FullName
        Get-Content -Tail $Tail -Path $_.FullName 
    }
}