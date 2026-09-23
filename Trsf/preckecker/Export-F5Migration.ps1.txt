#requires -Version 5.1
<#
.SYNOPSIS
  Export one A/B migration package from the LB_List Excel table to a JSON manifest.
.EXAMPLE
  .\Export-F5Migration.ps1 -Workbook 'C:\Work\EdgeConnect - Migration plan 2026.xlsx' -MigrationPackage SLO-0705 -Output '.\migration_SLO-0705.json'
.NOTES
  Run on Windows with desktop Excel installed. The workbook is opened read-only.
  Source BIG-IP version and live configuration are intentionally collected by the validator.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Workbook,
    [Parameter(Mandatory=$true)][string]$MigrationPackage,
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$TableName = 'LB_List'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-Header([string]$Text) {
    return [regex]::Replace($Text.ToLowerInvariant(), '[^a-z0-9]', '')
}

function Read-MatrixCell($Matrix, [int]$Row, [int]$Column) {
    if ($Matrix -is [array] -and $Matrix.Rank -eq 2) {
        return $Matrix.GetValue($Matrix.GetLowerBound(0) + $Row - 1,
                                $Matrix.GetLowerBound(1) + $Column - 1)
    }
    if ($Row -eq 1 -and $Column -eq 1) { return $Matrix }
    throw 'Unexpected Excel range shape; expected a two-dimensional table.'
}

function Read-Field($Row, [string]$Field, [bool]$Required = $false) {
    $value = $Row[$Field]
    if ($null -ne $value) { $value = ([string]$value).Trim() }
    if ([string]::IsNullOrWhiteSpace($value)) {
        if ($Required) { throw "Missing $Field for package $MigrationPackage (table row $($Row['_table_row']))." }
        return $null
    }
    return $value
}

function Read-IPv4([string]$Value, [string]$Field) {
    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$address) -or
        $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $Value -notmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
        throw "Invalid IPv4 address for $Field: '$Value'."
    }
    return $address.ToString()
}

function Parse-Software([string]$Value) {
    # Examples: 'BIG-IP 17.5.1.3 0.1.19' or '17.5.1.9 / 0.46.12'.
    $matchesFound = [regex]::Matches($Value, '\b\d+(?:\.\d+){2,4}\b')
    if ($matchesFound.Count -lt 1) { throw "Cannot parse target BIG-IP version from '$Value'." }
    $version = $matchesFound[0].Value
    $build = $null
    if ($matchesFound.Count -ge 2) { $build = $matchesFound[1].Value }
    return [ordered]@{ version = $version; build = $build; edition = $null; hotfix_id = $null; workbook_value = $Value }
}

# Header aliases are intentionally narrow. A renamed required column should stop the export.
$aliases = [ordered]@{
    package              = @('Migration Package')
    migration_date       = @('Migration Date')
    source_hostname      = @('Hostname')
    source_management_ip = @('Source Tenant Mgmt IP', 'Source Tenant Management IP')
    target_hostname      = @('Target Tenant Hostname')
    target_management_ip = @('Target Tenant MGMT IP', 'Target Tenant Management IP')
    host_hostname        = @('Target Host Hostname')
    host_management_ip   = @('Target Host MGMT IP', 'Target Host Management IP')
    host_model           = @('Host HW Model', 'Target Host HW Model')
    target_software      = @('Target Tenant OS Version')
    source_software_hint = @('OS Version')
    vip_count            = @('Number of VIPs')
    cert_count           = @('Number of Certificates')
    fips_partition_size  = @('FIPS Partition Size')
    tenant_vcpu          = @('Target Tenant vCPUs', 'Target Tenant vCPU')
    tenant_memory_gb     = @('Target Tenant Memory GB')
}
$requiredColumns = @('package','source_hostname','source_management_ip',
    'target_hostname','target_management_ip','host_hostname','host_management_ip',
    'host_model','target_software')

$excel = $book = $table = $null
try {
    $resolvedWorkbook = (Resolve-Path -LiteralPath $Workbook).Path
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    $excel.AskToUpdateLinks = $false
    $book = $excel.Workbooks.Open($resolvedWorkbook, 0, $true)
    foreach ($sheet in $book.Worksheets) {
        try {
            foreach ($candidate in $sheet.ListObjects) {
                if ($candidate.Name -eq $TableName) { $table = $candidate; break }
            }
            if ($null -ne $table) { break }
        } finally {
            if ($null -ne $sheet) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sheet) }
        }
    }
    if ($null -eq $table) { throw "Excel table '$TableName' was not found." }
    if ($null -eq $table.DataBodyRange) { throw "Excel table '$TableName' has no rows." }

    $headers = $table.HeaderRowRange.Value2
    $cells = $table.DataBodyRange.Value2
    $columnCount = [int]$table.ListColumns.Count
    $rowCount = [int]$table.DataBodyRange.Rows.Count
    $headerIndex = @{}
    for ($c = 1; $c -le $columnCount; $c++) {
        $header = ([string](Read-MatrixCell $headers 1 $c)).Trim()
        $key = Normalize-Header $header
        if ($headerIndex.ContainsKey($key)) { throw "Ambiguous column headers after normalization: '$header'." }
        $headerIndex[$key] = $c
    }
    $fieldIndex = @{}
    foreach ($field in $aliases.Keys) {
        foreach ($alias in $aliases[$field]) {
            $key = Normalize-Header $alias
            if ($headerIndex.ContainsKey($key)) { $fieldIndex[$field] = $headerIndex[$key]; break }
        }
    }
    foreach ($field in $requiredColumns) {
        if (-not $fieldIndex.ContainsKey($field)) {
            throw "Missing required column '$($aliases[$field][0])' in Excel table '$TableName'."
        }
    }

    $selected = @()
    for ($r = 1; $r -le $rowCount; $r++) {
        $pkg = [string](Read-MatrixCell $cells $r $fieldIndex['package'])
        if ($pkg.Trim() -ine $MigrationPackage.Trim()) { continue }
        $row = @{ _table_row = $r }
        foreach ($field in $fieldIndex.Keys) {
            $row[$field] = Read-MatrixCell $cells $r $fieldIndex[$field]
        }
        $selected += ,$row
    }
    if ($selected.Count -ne 2) {
        throw "Expected exactly two rows (A/B) for '$MigrationPackage'; found $($selected.Count)."
    }

    $devices = [ordered]@{}
    foreach ($row in $selected) {
        $sourceName = Read-Field $row 'source_hostname' $true
        $targetName = Read-Field $row 'target_hostname' $true
        if ($sourceName -notmatch '([AB])$' -or $targetName -notmatch '([AB])$') {
            throw "Cannot identify A/B suffix for source '$sourceName' and target '$targetName'."
        }
        $side = $sourceName.Substring($sourceName.Length - 1).ToUpperInvariant()
        $targetSide = $targetName.Substring($targetName.Length - 1).ToUpperInvariant()
        if ($side -ne $targetSide) { throw "A/B side mismatch: '$sourceName' -> '$targetName'." }
        if ($devices.Contains($side)) { throw "Duplicate $side row in '$MigrationPackage'." }
        $software = Parse-Software (Read-Field $row 'target_software' $true)
        $device = [ordered]@{
            source = [ordered]@{
                ssh_host = $sourceName
                expected_hostname = $sourceName
                management_ip = Read-IPv4 (Read-Field $row 'source_management_ip' $true) 'source_management_ip'
            }
            target = [ordered]@{
                ssh_host = $targetName
                expected_hostname = $targetName
                management_ip = Read-IPv4 (Read-Field $row 'target_management_ip' $true) 'target_management_ip'
                software = $software
                tenant = [ordered]@{
                    vcpu = Read-Field $row 'tenant_vcpu'
                    memory_gb = Read-Field $row 'tenant_memory_gb'
                    fips_partition_size = Read-Field $row 'fips_partition_size'
                }
            }
            rseries_host = [ordered]@{
                ssh_host = Read-Field $row 'host_hostname' $true
                expected_hostname = Read-Field $row 'host_hostname' $true
                management_ip = Read-IPv4 (Read-Field $row 'host_management_ip' $true) 'host_management_ip'
                model = Read-Field $row 'host_model' $true
            }
        }
        $devices[$side.ToLowerInvariant()] = $device
    }
    if (-not ($devices.Contains('a') -and $devices.Contains('b'))) {
        throw "Package '$MigrationPackage' does not contain one A row and one B row."
    }
    $date = $null
    if ($fieldIndex.ContainsKey('migration_date')) {
        $rawDate = $selected[0]['migration_date']
        if ($null -ne $rawDate -and "$rawDate".Trim() -ne '') {
            if ($rawDate -is [double] -or $rawDate -is [int]) {
                $date = [datetime]::FromOADate([double]$rawDate).ToString('yyyy-MM-dd')
            } else {
                # Preserve text dates; do not guess culture-specific day/month order.
                $date = [string]$rawDate
            }
        }
    }
    $manifest = [ordered]@{
        schema_version = 1
        migration_package = $MigrationPackage.Trim()
        migration_date = $date
        devices = $devices
    }
    $json = ConvertTo-Json -InputObject $manifest -Depth 12
    $outputPath = [IO.Path]::GetFullPath($Output)
    $parent = [IO.Path]::GetDirectoryName($outputPath)
    if (-not [IO.Directory]::Exists($parent)) { throw "Output directory does not exist: '$parent'." }
    $tempPath = "$outputPath.tmp.$PID"
    try {
        # UTF-8 without BOM is simplest for Python's json.load on the jump host.
        [IO.File]::WriteAllText($tempPath, $json + [Environment]::NewLine,
            (New-Object System.Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($outputPath)) {
            [IO.File]::Replace($tempPath, $outputPath, $null)
        } else {
            [IO.File]::Move($tempPath, $outputPath)
        }
    } finally {
        if ([IO.File]::Exists($tempPath)) { [IO.File]::Delete($tempPath) }
    }
    Write-Host "Exported $MigrationPackage (A/B) to $outputPath"
    Write-Host "Target software: A=$($devices['a']['target']['software']['version']); B=$($devices['b']['target']['software']['version'])"
    Write-Host 'Source software version, hotfix ID, VLANs, self IPs, and certificates are collected from the devices; they are not inferred from workbook statistics.'
} finally {
    if ($null -ne $book) { $book.Close($false); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($book) }
    if ($null -ne $table) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($table) }
    if ($null -ne $excel) { $excel.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($excel) }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
