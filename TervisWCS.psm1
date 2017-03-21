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

    $Results = Invoke-SQLODBC -DataSourceName tervis -SQLCommand $Query | 
    ConvertFrom-DataRow

    $ConveyorScaleNumberOfUniqueWeights = $Results | 
    Group-Object -Property Weight | 
    measure | 
    select -ExpandProperty count

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