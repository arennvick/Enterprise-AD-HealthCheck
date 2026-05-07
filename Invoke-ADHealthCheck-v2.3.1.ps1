<# 
.SYNOPSIS
    Full Active Directory forest health check with a self-contained HTML dashboard.

.DESCRIPTION
    Scans every domain controller discovered in the current AD forest, tests whether the
    server running the script can communicate to each DC on required management/AD ports,
    and collects forest, domain, FSMO, replication, DNS, site, GPO, time, service, SYSVOL,
    NETLOGON, and optional event log health.

    The output is a single HTML file that can be opened from a file share by any computer
    with a browser. No internet access or external JavaScript/CSS files are required.

.NOTES
    Run from a domain joined server with an account that can read AD and query DCs.
    Best results require:
      - ActiveDirectory PowerShell module
      - GroupPolicy PowerShell module
      - DnsServer PowerShell module
      - dcdiag.exe and repadmin.exe

    For the most complete result, run in an elevated PowerShell session on a management
    server or domain controller.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,

    [switch]$SkipDcDiag,

    [switch]$SkipDnsTests,

    [switch]$SkipGpoTests,

    [switch]$IncludeEventLogs,

    [ValidateRange(1, 168)]
    [int]$EventLogHours = 24,

    [ValidateRange(500, 30000)]
    [int]$TcpTimeoutMs = 2500,

    [ValidateRange(1, 365)]
    [int]$PatchWarningDays = 45,

    [string]$GpoBackupRoot,

    [string]$GitHubRepositoryUrl = 'https://github.com/arennvick/Enterprise-AD-HealthCheck',

    [switch]$SkipUpdateCheck,

    [switch]$OpenReport
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$scriptVersion = '2.3.2'

function New-Result {
    param(
        [string]$Area,
        [string]$Target,
        [string]$Name,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'Skipped')]
        [string]$Status,
        [string]$Message,
        [object]$Data = $null
    )

    [pscustomobject]@{
        Area      = $Area
        Target    = $Target
        Name      = $Name
        Status    = $Status
        Message   = $Message
        Data      = $Data
        Timestamp = (Get-Date).ToString('s')
    }
}

function Get-StatusRank {
    param([string]$Status)

    switch ($Status) {
        'Fail'    { 4; break }
        'Warn'    { 3; break }
        'Skipped' { 2; break }
        'Info'    { 1; break }
        'Pass'    { 0; break }
        default   { 1; break }
    }
}

function Join-Status {
    param([object[]]$Items)

    if (-not $Items -or $Items.Count -eq 0) {
        return 'Info'
    }

    $highest = 'Pass'
    foreach ($item in $Items) {
        if ((Get-StatusRank $item.Status) -gt (Get-StatusRank $highest)) {
            $highest = $item.Status
        }
    }
    return $highest
}

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Import-ModuleIfAvailable {
    param([string]$Name)

    try {
        Import-Module $Name -ErrorAction Stop
        return New-Result -Area 'Prerequisite' -Target $env:COMPUTERNAME -Name "Module $Name" -Status 'Pass' -Message "PowerShell module '$Name' loaded."
    }
    catch {
        return New-Result -Area 'Prerequisite' -Target $env:COMPUTERNAME -Name "Module $Name" -Status 'Warn' -Message "PowerShell module '$Name' is not available or failed to load. $($_.Exception.Message)"
    }
}

function Invoke-NativeCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    $output = New-Object System.Collections.Generic.List[string]
    $exitCode = $null

    try {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $cmdOutput = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $oldPreference

        if ($cmdOutput) {
            foreach ($line in $cmdOutput) {
                $output.Add([string]$line)
            }
        }
    }
    catch {
        $output.Add($_.Exception.Message)
        $exitCode = 9999
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Output   = ($output -join [Environment]::NewLine)
        Lines    = @($output)
    }
}

function Test-TcpPort {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMs = 2500
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $watch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $success = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        $watch.Stop()

        if (-not $success) {
            $client.Close()
            return [pscustomobject]@{
                Open      = $false
                LatencyMs = $null
                Message   = "Timed out after $TimeoutMs ms"
            }
        }

        $client.EndConnect($async)
        $client.Close()
        return [pscustomobject]@{
            Open      = $true
            LatencyMs = [int]$watch.ElapsedMilliseconds
            Message   = 'Connected'
        }
    }
    catch {
        $watch.Stop()
        try { $client.Close() } catch {}
        return [pscustomobject]@{
            Open      = $false
            LatencyMs = $null
            Message   = $_.Exception.Message
        }
    }
}

function ConvertTo-HtmlSafeJson {
    param([object]$InputObject)

    $json = $InputObject | ConvertTo-Json -Depth 20
    return $json.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
}

function Add-Recommendation {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Severity,
        [string]$Title,
        [string]$Details,
        [string]$Action
    )

    $List.Add([pscustomobject]@{
        Severity = $Severity
        Title    = $Title
        Details  = $Details
        Action   = $Action
    })
}

function Convert-ToDateTimeOrNull {
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    if ($Value -is [datetime]) {
        return $Value
    }

    try {
        return [datetime]$Value
    }
    catch {
        try {
            return [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$Value)
        }
        catch {
            return $null
        }
    }
}

function Get-SafeFileName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return 'Unknown'
    }

    return ($Name -replace '[^a-zA-Z0-9._-]', '_')
}

function Get-AdObjectCount {
    param(
        [string]$Server,
        [string]$LDAPFilter
    )

    try {
        return @(Get-ADObject -LDAPFilter $LDAPFilter -Server $Server -ResultSetSize $null -ErrorAction Stop).Count
    }
    catch {
        return $null
    }
}

function Get-GroupMemberSummary {
    param(
        [string]$DomainServer,
        [string]$Sid,
        [string]$GroupLabel,
        [string]$Scope
    )

    try {
        $group = Get-ADGroup -Identity $Sid -Server $DomainServer -ErrorAction Stop
        $members = @(Get-ADGroupMember -Identity $group.DistinguishedName -Server $DomainServer -Recursive -ErrorAction Stop)
        $userMembers = @($members | Where-Object { $_.objectClass -eq 'user' })

        [pscustomobject]@{
            Scope        = $Scope
            Group        = $GroupLabel
            Name         = $group.Name
            Domain       = $DomainServer
            MemberCount  = $members.Count
            UserCount    = $userMembers.Count
            Status       = 'Pass'
            Message      = 'Membership collected recursively.'
        }
    }
    catch {
        [pscustomobject]@{
            Scope        = $Scope
            Group        = $GroupLabel
            Name         = ''
            Domain       = $DomainServer
            MemberCount  = $null
            UserCount    = $null
            Status       = 'Warn'
            Message      = $_.Exception.Message
        }
    }
}

function Get-NumericSum {
    param(
        [object[]]$Items,
        [string]$Property
    )

    $total = 0
    foreach ($item in @($Items)) {
        if ($null -ne $item -and $item.PSObject.Properties[$Property] -and $null -ne $item.$Property) {
            $total += [double]$item.$Property
        }
    }
    return $total
}

function Convert-GitHubRepoToApiUrl {
    param([string]$RepositoryUrl)

    if ([string]::IsNullOrWhiteSpace($RepositoryUrl)) {
        return ''
    }

    $trimmed = $RepositoryUrl.Trim().TrimEnd('/')
    if ($trimmed -match '^https://api\.github\.com/repos/[^/]+/[^/]+') {
        return "$trimmed/releases/latest"
    }
    if ($trimmed -match '^https://github\.com/([^/]+)/([^/]+)') {
        return "https://api.github.com/repos/$($Matches[1])/$($Matches[2])/releases/latest"
    }
    if ($trimmed -match '^([^/]+)/([^/]+)$') {
        return "https://api.github.com/repos/$($Matches[1])/$($Matches[2])/releases/latest"
    }

    return ''
}

function Convert-GitHubRepoToReleaseUrl {
    param([string]$RepositoryUrl)

    if ([string]::IsNullOrWhiteSpace($RepositoryUrl)) {
        return ''
    }

    $trimmed = $RepositoryUrl.Trim().TrimEnd('/')
    if ($trimmed -match '^https://github\.com/[^/]+/[^/]+') {
        return "$trimmed/releases/latest"
    }
    if ($trimmed -match '^https://api\.github\.com/repos/([^/]+)/([^/]+)') {
        return "https://github.com/$($Matches[1])/$($Matches[2])/releases/latest"
    }
    if ($trimmed -match '^([^/]+)/([^/]+)$') {
        return "https://github.com/$($Matches[1])/$($Matches[2])/releases/latest"
    }

    return $trimmed
}

function Convert-ToComparableVersion {
    param([string]$VersionText)

    if ([string]::IsNullOrWhiteSpace($VersionText)) {
        return [version]'0.0.0'
    }

    $clean = ($VersionText -replace '^[vV]', '') -replace '[^0-9.]', ''
    if ([string]::IsNullOrWhiteSpace($clean)) {
        return [version]'0.0.0'
    }

    $parts = @($clean.Split('.') | Where-Object { $_ -ne '' })
    while ($parts.Count -lt 3) {
        $parts += '0'
    }

    try {
        return [version]($parts[0..2] -join '.')
    }
    catch {
        return [version]'0.0.0'
    }
}

function Test-NewerVersion {
    param(
        [string]$CurrentVersion,
        [string]$LatestVersion
    )

    $current = Convert-ToComparableVersion -VersionText $CurrentVersion
    $latest = Convert-ToComparableVersion -VersionText $LatestVersion
    return ($latest -gt $current)
}

function Get-GpoIdentifierFromXml {
    param([object]$GpoXmlNode)

    $identifier = ''

    try {
        if ($GpoXmlNode.Identifier -and $GpoXmlNode.Identifier.Identifier) {
            $identifier = [string]$GpoXmlNode.Identifier.Identifier.'#text'
        }
    }
    catch {}

    if ([string]::IsNullOrWhiteSpace($identifier)) {
        try {
            $innerText = [string]$GpoXmlNode.Identifier.InnerText
            if ($innerText -match '\{[0-9A-Fa-f-]{36}\}') {
                $identifier = $Matches[0]
            }
        }
        catch {}
    }

    if ([string]::IsNullOrWhiteSpace($identifier)) {
        try {
            $outerXml = [string]$GpoXmlNode.OuterXml
            if ($outerXml -match '\{[0-9A-Fa-f-]{36}\}') {
                $identifier = $Matches[0]
            }
        }
        catch {}
    }

    return $identifier
}

function ConvertTo-GpoIdKey {
    param([object]$Id)

    if ($null -eq $Id -or [string]::IsNullOrWhiteSpace([string]$Id)) {
        return ''
    }

    if ($Id -is [guid]) {
        return $Id.ToString('D').ToLowerInvariant()
    }

    if (-not ($Id -is [string]) -and -not ($Id.GetType().IsPrimitive)) {
        foreach ($propertyName in @('Id', 'Guid', 'GpoId', 'GPOId', 'Identifier', 'Value')) {
            $property = $Id.PSObject.Properties[$propertyName]
            if ($property -and $null -ne $property.Value) {
                $candidate = ConvertTo-GpoIdKey -Id $property.Value
                if ($candidate) {
                    return $candidate
                }
            }
        }
    }

    $idText = ([string]$Id).Trim()
    if ($idText -match '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}') {
        return $Matches[0].ToLowerInvariant()
    }

    $clean = $idText.Trim('{', '}')
    if ([string]::IsNullOrWhiteSpace($clean)) {
        return ''
    }

    return $clean.ToLowerInvariant()
}

function ConvertTo-GpoNameKey {
    param([object]$Name)

    if ($null -eq $Name -or [string]::IsNullOrWhiteSpace([string]$Name)) {
        return ''
    }

    return (([string]$Name).Trim() -replace '\s+', ' ').ToLowerInvariant()
}

function ConvertTo-GpoDisplayId {
    param([object]$Id)

    $key = ConvertTo-GpoIdKey -Id $Id
    if ([string]::IsNullOrWhiteSpace($key)) {
        return ''
    }

    return "{$key}"
}

Write-Host "Starting AD health check..." -ForegroundColor Cyan

$startedAt = Get-Date
$prerequisites = New-Object System.Collections.Generic.List[object]
$findings = New-Object System.Collections.Generic.List[object]
$recommendations = New-Object System.Collections.Generic.List[object]
$rawCommands = New-Object System.Collections.Generic.List[object]

$adModuleResult = Import-ModuleIfAvailable -Name 'ActiveDirectory'
$prerequisites.Add($adModuleResult)

$gpoModuleResult = Import-ModuleIfAvailable -Name 'GroupPolicy'
$prerequisites.Add($gpoModuleResult)

$dnsModuleResult = Import-ModuleIfAvailable -Name 'DnsServer'
$prerequisites.Add($dnsModuleResult)

$dcdiagAvailable = Test-CommandExists -Name 'dcdiag.exe'
$repadminAvailable = Test-CommandExists -Name 'repadmin.exe'
$prerequisites.Add((New-Result -Area 'Prerequisite' -Target $env:COMPUTERNAME -Name 'dcdiag.exe' -Status ($(if ($dcdiagAvailable) { 'Pass' } else { 'Warn' })) -Message ($(if ($dcdiagAvailable) { 'dcdiag.exe found.' } else { 'dcdiag.exe was not found in PATH. Install RSAT AD DS tools or run on a DC.' }))))
$prerequisites.Add((New-Result -Area 'Prerequisite' -Target $env:COMPUTERNAME -Name 'repadmin.exe' -Status ($(if ($repadminAvailable) { 'Pass' } else { 'Warn' })) -Message ($(if ($repadminAvailable) { 'repadmin.exe found.' } else { 'repadmin.exe was not found in PATH. Repadmin summary will be skipped.' }))))

if ($adModuleResult.Status -ne 'Pass') {
    Add-Recommendation -List $recommendations -Severity 'Critical' -Title 'ActiveDirectory module is required' -Details 'The script cannot discover the forest or domain controllers without the ActiveDirectory PowerShell module.' -Action 'Install RSAT: Active Directory Domain Services and Lightweight Directory Tools, or run this script from a domain controller.'
}

$forest = $null
$domains = @()
$domainControllers = @()
$forestInfo = $null
$domainInfo = @()
$fsmoRoles = @()
$sites = @()
$siteLinks = @()
$subnets = @()

if ($adModuleResult.Status -eq 'Pass') {
    try {
        Write-Host "Discovering forest, domains, and domain controllers..." -ForegroundColor Cyan
        $forest = Get-ADForest -ErrorAction Stop
        $domains = @($forest.Domains)

        $forestInfo = [pscustomobject]@{
            Name             = $forest.Name
            ForestMode       = [string]$forest.ForestMode
            RootDomain       = $forest.RootDomain
            SchemaMaster     = $forest.SchemaMaster
            DomainNamingRole = $forest.DomainNamingMaster
            GlobalCatalogs   = @($forest.GlobalCatalogs)
            Sites            = @($forest.Sites)
            Domains          = @($forest.Domains)
        }

        $fsmoRoles += [pscustomobject]@{ Scope = 'Forest'; Role = 'Schema Master'; Holder = $forest.SchemaMaster }
        $fsmoRoles += [pscustomobject]@{ Scope = 'Forest'; Role = 'Domain Naming Master'; Holder = $forest.DomainNamingMaster }

        foreach ($domainName in $domains) {
            try {
                $domain = Get-ADDomain -Server $domainName -ErrorAction Stop
                $domainInfo += [pscustomobject]@{
                    Name                 = $domain.DNSRoot
                    NetBIOSName          = $domain.NetBIOSName
                    DomainMode           = [string]$domain.DomainMode
                    PDCEmulator          = $domain.PDCEmulator
                    RIDMaster            = $domain.RIDMaster
                    InfrastructureMaster = $domain.InfrastructureMaster
                    UsersContainer       = $domain.UsersContainer
                    ComputersContainer   = $domain.ComputersContainer
                    DeletedObjects       = $domain.DeletedObjectsContainer
                }

                $fsmoRoles += [pscustomobject]@{ Scope = $domain.DNSRoot; Role = 'PDC Emulator'; Holder = $domain.PDCEmulator }
                $fsmoRoles += [pscustomobject]@{ Scope = $domain.DNSRoot; Role = 'RID Master'; Holder = $domain.RIDMaster }
                $fsmoRoles += [pscustomobject]@{ Scope = $domain.DNSRoot; Role = 'Infrastructure Master'; Holder = $domain.InfrastructureMaster }

                $dcs = Get-ADDomainController -Filter * -Server $domainName -ErrorAction Stop
                foreach ($dc in $dcs) {
                    $domainControllers += [pscustomobject]@{
                        Name                 = $dc.Name
                        HostName             = $dc.HostName
                        Domain               = $domainName
                        Site                 = $dc.Site
                        IPv4Address          = $dc.IPv4Address
                        IPv6Address          = $dc.IPv6Address
                        OperatingSystem      = $dc.OperatingSystem
                        OperatingSystemHotfix = $dc.OperatingSystemHotfix
                        IsGlobalCatalog      = $dc.IsGlobalCatalog
                        IsReadOnly           = $dc.IsReadOnly
                        Enabled              = $dc.Enabled
                        LdapPort             = $dc.LdapPort
                        SslPort              = $dc.SslPort
                        OperationMasterRoles = @($dc.OperationMasterRoles)
                    }
                }
            }
            catch {
                $findings.Add((New-Result -Area 'Discovery' -Target $domainName -Name 'Domain discovery' -Status 'Fail' -Message $_.Exception.Message))
                Add-Recommendation -List $recommendations -Severity 'Critical' -Title "Cannot query domain $domainName" -Details $_.Exception.Message -Action 'Verify permissions, DNS resolution, AD module availability, and connectivity to a DC in this domain.'
            }
        }

        $domainControllers = @($domainControllers | Sort-Object HostName -Unique)

        try {
            $sites = @(Get-ADReplicationSite -Filter * -Properties Description, Location, WhenCreated, WhenChanged -ErrorAction Stop | ForEach-Object {
                $siteName = $_.Name
                [pscustomobject]@{
                    Name        = $_.Name
                    Description = $_.Description
                    Location    = $_.Location
                    WhenCreated = $_.WhenCreated
                    WhenChanged = $_.WhenChanged
                    DcCount     = @($domainControllers | Where-Object { $_.Site -eq $siteName }).Count
                }
            })
        }
        catch {
            $findings.Add((New-Result -Area 'Sites' -Target $forest.Name -Name 'Site discovery' -Status 'Warn' -Message $_.Exception.Message))
        }

        try {
            $siteLinks = @(Get-ADReplicationSiteLink -Filter * -Properties Cost, ReplicationFrequencyInMinutes, SitesIncluded, Options -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Name                          = $_.Name
                    Cost                          = $_.Cost
                    ReplicationFrequencyInMinutes = $_.ReplicationFrequencyInMinutes
                    SitesIncluded                 = @($_.SitesIncluded)
                    Options                       = $_.Options
                }
            })
        }
        catch {
            $findings.Add((New-Result -Area 'Sites' -Target $forest.Name -Name 'Site link discovery' -Status 'Warn' -Message $_.Exception.Message))
        }

        try {
            $subnets = @(Get-ADReplicationSubnet -Filter * -Properties Site, Location, Description -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Name        = $_.Name
                    Site        = if ($_.Site) { ($_.Site -split ',')[0] -replace '^CN=', '' } else { '' }
                    Location    = $_.Location
                    Description = $_.Description
                }
            })
        }
        catch {
            $findings.Add((New-Result -Area 'Sites' -Target $forest.Name -Name 'Subnet discovery' -Status 'Warn' -Message $_.Exception.Message))
        }
    }
    catch {
        $findings.Add((New-Result -Area 'Discovery' -Target $env:USERDNSDOMAIN -Name 'Forest discovery' -Status 'Fail' -Message $_.Exception.Message))
        Add-Recommendation -List $recommendations -Severity 'Critical' -Title 'Forest discovery failed' -Details $_.Exception.Message -Action 'Run from a domain joined server with RSAT AD tools and an account that can read forest configuration.'
    }
}

$portDefinitions = @(
    [pscustomobject]@{ Port = 53;   Protocol = 'TCP'; Required = 'Required'; Purpose = 'DNS queries and zone transfers when applicable' },
    [pscustomobject]@{ Port = 88;   Protocol = 'TCP'; Required = 'Required'; Purpose = 'Kerberos authentication' },
    [pscustomobject]@{ Port = 135;  Protocol = 'TCP'; Required = 'Required'; Purpose = 'RPC endpoint mapper for service, event log, DCDiag, and replication checks' },
    [pscustomobject]@{ Port = 389;  Protocol = 'TCP'; Required = 'Required'; Purpose = 'LDAP directory queries' },
    [pscustomobject]@{ Port = 445;  Protocol = 'TCP'; Required = 'Required'; Purpose = 'SMB access to SYSVOL and NETLOGON' },
    [pscustomobject]@{ Port = 464;  Protocol = 'TCP'; Required = 'Recommended'; Purpose = 'Kerberos password change service' },
    [pscustomobject]@{ Port = 636;  Protocol = 'TCP'; Required = 'Recommended'; Purpose = 'LDAPS if secure LDAP checks or clients require it' },
    [pscustomobject]@{ Port = 3268; Protocol = 'TCP'; Required = 'Required for GC'; Purpose = 'Global Catalog LDAP' },
    [pscustomobject]@{ Port = 3269; Protocol = 'TCP'; Required = 'Recommended for GC'; Purpose = 'Global Catalog LDAPS' },
    [pscustomobject]@{ Port = 5985; Protocol = 'TCP'; Required = 'Optional'; Purpose = 'WinRM HTTP for remote event and management checks' },
    [pscustomobject]@{ Port = 5986; Protocol = 'TCP'; Required = 'Optional'; Purpose = 'WinRM HTTPS for remote event and management checks' },
    [pscustomobject]@{ Port = 9389; Protocol = 'TCP'; Required = 'Required'; Purpose = 'Active Directory Web Services used by AD PowerShell cmdlets' }
)

$udpPortNotes = @(
    [pscustomobject]@{ Port = 53; Protocol = 'UDP'; Purpose = 'DNS queries. UDP is not reliably tested by this script.' },
    [pscustomobject]@{ Port = 88; Protocol = 'UDP'; Purpose = 'Kerberos. UDP is not reliably tested by this script.' },
    [pscustomobject]@{ Port = 123; Protocol = 'UDP'; Purpose = 'NTP time sync. UDP is not reliably tested by this script.' },
    [pscustomobject]@{ Port = 389; Protocol = 'UDP'; Purpose = 'LDAP ping/DC locator. UDP is not reliably tested by this script.' },
    [pscustomobject]@{ Port = 464; Protocol = 'UDP'; Purpose = 'Kerberos password change. UDP is not reliably tested by this script.' },
    [pscustomobject]@{ Port = '49152-65535'; Protocol = 'TCP'; Purpose = 'Default Windows dynamic RPC range. Required from this script server to DCs for many RPC-backed checks when firewalls are restrictive.' }
)

$connectivity = @()
$connectivitySummary = @()
$dcInventory = @()
$directoryStats = @()
$groupTypeStats = @()
$privilegedGroupStats = @()

if ($adModuleResult.Status -eq 'Pass' -and $domains.Count -gt 0) {
    Write-Host "Collecting user, group, and privileged administrator counts..." -ForegroundColor Cyan

    foreach ($domainName in $domains) {
        try {
            $domain = Get-ADDomain -Server $domainName -ErrorAction Stop
            $domainSid = [string]$domain.DomainSID.Value

            $totalUsers = Get-AdObjectCount -Server $domainName -LDAPFilter '(&(objectCategory=person)(objectClass=user))'
            $disabledUsers = Get-AdObjectCount -Server $domainName -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
            $enabledUsers = if ($null -ne $totalUsers -and $null -ne $disabledUsers) { $totalUsers - $disabledUsers } else { $null }
            $totalGroups = Get-AdObjectCount -Server $domainName -LDAPFilter '(objectCategory=group)'

            $groups = @(Get-ADGroup -Filter * -Server $domainName -Properties GroupCategory, GroupScope -ErrorAction Stop)
            $securityGroups = @($groups | Where-Object { $_.GroupCategory -eq 'Security' }).Count
            $distributionGroups = @($groups | Where-Object { $_.GroupCategory -eq 'Distribution' }).Count
            $globalGroups = @($groups | Where-Object { $_.GroupScope -eq 'Global' }).Count
            $domainLocalGroups = @($groups | Where-Object { $_.GroupScope -eq 'DomainLocal' }).Count
            $universalGroups = @($groups | Where-Object { $_.GroupScope -eq 'Universal' }).Count

            $directoryStats += [pscustomobject]@{
                Domain             = $domainName
                Status             = 'Pass'
                TotalUsers         = $totalUsers
                EnabledUsers       = $enabledUsers
                DisabledUsers      = $disabledUsers
                TotalGroups        = $totalGroups
                SecurityGroups     = $securityGroups
                DistributionGroups = $distributionGroups
                GlobalGroups       = $globalGroups
                DomainLocalGroups  = $domainLocalGroups
                UniversalGroups    = $universalGroups
                Message            = 'Directory object counts collected.'
            }

            $groupTypeStats += [pscustomobject]@{ Domain = $domainName; Type = 'Security'; Scope = 'All'; Count = $securityGroups }
            $groupTypeStats += [pscustomobject]@{ Domain = $domainName; Type = 'Distribution'; Scope = 'All'; Count = $distributionGroups }
            $groupTypeStats += [pscustomobject]@{ Domain = $domainName; Type = 'All'; Scope = 'Global'; Count = $globalGroups }
            $groupTypeStats += [pscustomobject]@{ Domain = $domainName; Type = 'All'; Scope = 'Domain Local'; Count = $domainLocalGroups }
            $groupTypeStats += [pscustomobject]@{ Domain = $domainName; Type = 'All'; Scope = 'Universal'; Count = $universalGroups }

            $privilegedGroupStats += Get-GroupMemberSummary -DomainServer $domainName -Sid "$domainSid-512" -GroupLabel 'Domain Admins' -Scope $domainName
        }
        catch {
            $directoryStats += [pscustomobject]@{
                Domain             = $domainName
                Status             = 'Warn'
                TotalUsers         = $null
                EnabledUsers       = $null
                DisabledUsers      = $null
                TotalGroups        = $null
                SecurityGroups     = $null
                DistributionGroups = $null
                GlobalGroups       = $null
                DomainLocalGroups  = $null
                UniversalGroups    = $null
                Message            = $_.Exception.Message
            }
        }
    }

    if ($forest -and $forest.RootDomain) {
        try {
            $rootDomain = Get-ADDomain -Server $forest.RootDomain -ErrorAction Stop
            $rootSid = [string]$rootDomain.DomainSID.Value
            $privilegedGroupStats += Get-GroupMemberSummary -DomainServer $forest.RootDomain -Sid "$rootSid-519" -GroupLabel 'Enterprise Admins' -Scope 'Forest'
            $privilegedGroupStats += Get-GroupMemberSummary -DomainServer $forest.RootDomain -Sid "$rootSid-518" -GroupLabel 'Schema Admins' -Scope 'Forest'
        }
        catch {
            $privilegedGroupStats += [pscustomobject]@{
                Scope       = 'Forest'
                Group       = 'Enterprise Admins / Schema Admins'
                Name        = ''
                Domain      = $forest.RootDomain
                MemberCount = $null
                UserCount   = $null
                Status      = 'Warn'
                Message     = $_.Exception.Message
            }
        }
    }
}

if ($domainControllers.Count -gt 0) {
    Write-Host "Testing connectivity from $env:COMPUTERNAME to $($domainControllers.Count) domain controller(s)..." -ForegroundColor Cyan

    foreach ($dc in $domainControllers) {
        $target = $dc.HostName
        $dcPortRows = New-Object System.Collections.Generic.List[object]

        foreach ($port in $portDefinitions) {
            $result = Test-TcpPort -ComputerName $target -Port $port.Port -TimeoutMs $TcpTimeoutMs
            $status = if ($result.Open) { 'Pass' } elseif ($port.Required -like 'Required*') { 'Fail' } elseif ($port.Required -eq 'Recommended') { 'Warn' } else { 'Info' }

            $row = [pscustomobject]@{
                Target    = $target
                Domain    = $dc.Domain
                Site      = $dc.Site
                Port      = $port.Port
                Protocol  = $port.Protocol
                Required  = $port.Required
                Purpose   = $port.Purpose
                Status    = $status
                LatencyMs = $result.LatencyMs
                Message   = $result.Message
            }
            $dcPortRows.Add($row)
            $connectivity += $row
        }

        $blockedRequired = @($dcPortRows | Where-Object { $_.Status -eq 'Fail' })
        $blockedRecommended = @($dcPortRows | Where-Object { $_.Status -eq 'Warn' })
        $dcStatus = if ($blockedRequired.Count -gt 0) { 'Fail' } elseif ($blockedRecommended.Count -gt 0) { 'Warn' } else { 'Pass' }
        $openRequired = @($dcPortRows | Where-Object { $_.Status -eq 'Pass' -and $_.Required -like 'Required*' }).Count
        $requiredCount = @($dcPortRows | Where-Object { $_.Required -like 'Required*' }).Count

        $connectivitySummary += [pscustomobject]@{
            Target                   = $target
            Domain                   = $dc.Domain
            Site                     = $dc.Site
            Status                   = $dcStatus
            RequiredPortsOpen        = "$openRequired/$requiredCount"
            BlockedRequiredPorts     = @($blockedRequired | ForEach-Object { "$($_.Protocol)/$($_.Port)" })
            BlockedRecommendedPorts  = @($blockedRecommended | ForEach-Object { "$($_.Protocol)/$($_.Port)" })
            RequiredFirewallGuidance = if ($blockedRequired.Count -gt 0) { "Open outbound from $env:COMPUTERNAME to $target on: " + ((@($blockedRequired | ForEach-Object { "$($_.Protocol) $($_.Port) ($($_.Purpose))" })) -join '; ') } else { 'Required TCP ports are reachable.' }
        }
    }
}

if ($domainControllers.Count -gt 0) {
    Write-Host "Collecting domain controller OS, version, and patch inventory..." -ForegroundColor Cyan

    foreach ($dc in $domainControllers) {
        $target = $dc.HostName
        $domainRecord = @($domainInfo | Where-Object { $_.Name -eq $dc.Domain } | Select-Object -First 1)
        $os = $null
        $computerSystem = $null
        $bios = $null
        $osStatus = 'Pass'
        $patchStatus = 'Info'
        $message = 'Inventory collected.'

        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $target -ErrorAction Stop
        }
        catch {
            $osStatus = 'Warn'
            $message = "Could not query Win32_OperatingSystem. $($_.Exception.Message)"
        }

        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $target -ErrorAction Stop
        }
        catch {}

        try {
            $bios = Get-CimInstance -ClassName Win32_BIOS -ComputerName $target -ErrorAction Stop
        }
        catch {}

        $hotfixCount = $null
        $latestHotfixId = ''
        $latestHotfixDescription = ''
        $latestHotfixDate = $null
        $patchMessage = ''

        try {
            $hotfixes = @(Get-HotFix -ComputerName $target -ErrorAction Stop)
            $hotfixCount = $hotfixes.Count
            $datedHotfixes = @($hotfixes | ForEach-Object {
                $installedOn = Convert-ToDateTimeOrNull -Value $_.InstalledOn
                if ($installedOn) {
                    [pscustomobject]@{
                        HotFixID    = $_.HotFixID
                        Description = $_.Description
                        InstalledOn = $installedOn
                    }
                }
            } | Sort-Object InstalledOn -Descending)

            if ($datedHotfixes.Count -gt 0) {
                $latest = $datedHotfixes[0]
                $latestHotfixId = $latest.HotFixID
                $latestHotfixDescription = $latest.Description
                $latestHotfixDate = $latest.InstalledOn
                $patchAgeDays = [int]((Get-Date) - $latestHotfixDate).TotalDays
                if ($patchAgeDays -le $PatchWarningDays) {
                    $patchStatus = 'Pass'
                    $patchMessage = "Latest installed hotfix is $patchAgeDays day(s) old."
                }
                else {
                    $patchStatus = 'Warn'
                    $patchMessage = "Latest installed hotfix is $patchAgeDays day(s) old, older than the $PatchWarningDays day threshold."
                }
            }
            else {
                $patchStatus = 'Warn'
                $patchMessage = 'No hotfix install dates were returned.'
            }
        }
        catch {
            $patchStatus = 'Warn'
            $patchMessage = "Could not query installed hotfixes. $($_.Exception.Message)"
        }

        $installDate = if ($os) { Convert-ToDateTimeOrNull -Value $os.InstallDate } else { $null }
        $lastBoot = if ($os) { Convert-ToDateTimeOrNull -Value $os.LastBootUpTime } else { $null }
        $uptimeDays = if ($lastBoot) { [math]::Round(((Get-Date) - $lastBoot).TotalDays, 1) } else { $null }

        $dcInventory += [pscustomobject]@{
            Status                = Join-Status -Items @(
                [pscustomobject]@{ Status = $osStatus },
                [pscustomobject]@{ Status = $patchStatus }
            )
            Target                = $target
            Name                  = $dc.Name
            Domain                = $dc.Domain
            DomainFunctionalLevel = if ($domainRecord.Count -gt 0) { $domainRecord[0].DomainMode } else { '' }
            ForestFunctionalLevel = if ($forestInfo) { $forestInfo.ForestMode } else { '' }
            Site                  = $dc.Site
            IsGlobalCatalog       = $dc.IsGlobalCatalog
            IsReadOnly            = $dc.IsReadOnly
            IPv4Address           = $dc.IPv4Address
            OperatingSystem       = if ($os) { $os.Caption } else { $dc.OperatingSystem }
            Version               = if ($os) { $os.Version } else { '' }
            BuildNumber           = if ($os) { $os.BuildNumber } else { '' }
            OSArchitecture        = if ($os) { $os.OSArchitecture } else { '' }
            ServicePack           = if ($os) { $os.CSDVersion } else { '' }
            InstallDate           = $installDate
            LastBootUpTime        = $lastBoot
            UptimeDays            = $uptimeDays
            Manufacturer          = if ($computerSystem) { $computerSystem.Manufacturer } else { '' }
            Model                 = if ($computerSystem) { $computerSystem.Model } else { '' }
            TotalMemoryGB         = if ($computerSystem -and $computerSystem.TotalPhysicalMemory) { [math]::Round(($computerSystem.TotalPhysicalMemory / 1GB), 2) } else { $null }
            BIOSSerialNumber      = if ($bios) { $bios.SerialNumber } else { '' }
            PatchStatus           = $patchStatus
            LatestHotFixID        = $latestHotfixId
            LatestHotFixDate      = $latestHotfixDate
            LatestHotFixDescription = $latestHotfixDescription
            InstalledHotFixCount  = $hotfixCount
            PatchMessage          = $patchMessage
            Message               = $message
        }
    }
}

$serviceHealth = @()
$shareHealth = @()
$timeHealth = @()
$dcdiagHealth = @()
$replicationHealth = @()
$replicationFailures = @()
$dnsHealth = @()
$gpoHealth = @()
$gpoBackupInfo = @()
$gpoChangeHealth = @()
$eventHealth = @()

if ($domainControllers.Count -gt 0) {
    Write-Host "Collecting service, SYSVOL, NETLOGON, and time health..." -ForegroundColor Cyan

    $serviceNames = @('NTDS', 'DNS', 'KDC', 'Netlogon', 'W32Time', 'DFSR', 'ADWS')
    foreach ($dc in $domainControllers) {
        $target = $dc.HostName

        foreach ($serviceName in $serviceNames) {
            try {
                $svc = Get-Service -ComputerName $target -Name $serviceName -ErrorAction Stop
                $status = if ($svc.Status -eq 'Running') { 'Pass' } else { 'Fail' }
                $serviceHealth += [pscustomobject]@{
                    Target      = $target
                    ServiceName = $serviceName
                    DisplayName = $svc.DisplayName
                    Status      = $status
                    State       = [string]$svc.Status
                    Message     = if ($status -eq 'Pass') { 'Service is running.' } else { "Service state is $($svc.Status)." }
                }
            }
            catch {
                $status = if ($serviceName -eq 'DNS') { 'Warn' } else { 'Fail' }
                $serviceHealth += [pscustomobject]@{
                    Target      = $target
                    ServiceName = $serviceName
                    DisplayName = $serviceName
                    Status      = $status
                    State       = 'Unknown'
                    Message     = $_.Exception.Message
                }
            }
        }

        foreach ($share in @('SYSVOL', 'NETLOGON')) {
            $unc = "\\$target\$share"
            try {
                $exists = Test-Path -Path $unc -ErrorAction Stop
                $shareHealth += [pscustomobject]@{
                    Target  = $target
                    Share   = $share
                    Path    = $unc
                    Status  = if ($exists) { 'Pass' } else { 'Fail' }
                    Message = if ($exists) { "$share is reachable." } else { "$share is not reachable." }
                }
            }
            catch {
                $shareHealth += [pscustomobject]@{
                    Target  = $target
                    Share   = $share
                    Path    = $unc
                    Status  = 'Fail'
                    Message = $_.Exception.Message
                }
            }
        }

        $timeResult = Invoke-NativeCommand -FilePath 'w32tm.exe' -Arguments @('/query', "/computer:$target", '/status')
        $timeStatus = if ($timeResult.ExitCode -eq 0 -and $timeResult.Output -notmatch 'error|failed|denied') { 'Pass' } else { 'Warn' }
        $source = ''
        $stratum = ''
        foreach ($line in $timeResult.Lines) {
            if ($line -match '^Source:\s*(.+)$') { $source = $Matches[1].Trim() }
            if ($line -match '^Stratum:\s*(.+)$') { $stratum = $Matches[1].Trim() }
        }
        $timeHealth += [pscustomobject]@{
            Target   = $target
            Status   = $timeStatus
            Source   = $source
            Stratum  = $stratum
            ExitCode = $timeResult.ExitCode
            Message  = if ($timeStatus -eq 'Pass') { 'Time status queried successfully.' } else { $timeResult.Output }
        }
    }
}

if ($adModuleResult.Status -eq 'Pass' -and $domainControllers.Count -gt 0) {
    Write-Host "Collecting AD replication metadata..." -ForegroundColor Cyan

    foreach ($dc in $domainControllers) {
        try {
            $partners = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Server -ErrorAction Stop
            foreach ($partner in $partners) {
                $status = 'Pass'
                if ($partner.ConsecutiveReplicationFailures -gt 0 -or $partner.LastReplicationResult -ne 0) {
                    $status = 'Fail'
                }

                $replicationHealth += [pscustomobject]@{
                    Target                          = $dc.HostName
                    Partner                         = $partner.Partner
                    Partition                       = $partner.Partition
                    Direction                       = $partner.PartnerType
                    LastReplicationSuccess          = $partner.LastReplicationSuccess
                    LastReplicationAttempt          = $partner.LastReplicationAttempt
                    ConsecutiveReplicationFailures  = $partner.ConsecutiveReplicationFailures
                    LastReplicationResult           = $partner.LastReplicationResult
                    LastReplicationResultMessage    = $partner.LastReplicationResultMessage
                    Status                          = $status
                }
            }
        }
        catch {
            $replicationHealth += [pscustomobject]@{
                Target                          = $dc.HostName
                Partner                         = ''
                Partition                       = ''
                Direction                       = ''
                LastReplicationSuccess          = $null
                LastReplicationAttempt          = $null
                ConsecutiveReplicationFailures  = $null
                LastReplicationResult           = $null
                LastReplicationResultMessage    = $_.Exception.Message
                Status                          = 'Fail'
            }
        }

        try {
            $failures = Get-ADReplicationFailure -Target $dc.HostName -Scope Server -ErrorAction Stop
            foreach ($failure in $failures) {
                $replicationFailures += [pscustomobject]@{
                    Target            = $dc.HostName
                    Server            = $failure.Server
                    Partner           = $failure.Partner
                    FirstFailureTime  = $failure.FirstFailureTime
                    FailureCount      = $failure.FailureCount
                    LastError         = $failure.LastError
                    LastErrorMessage  = $failure.LastErrorMessage
                    Status            = 'Fail'
                }
            }
        }
        catch {
            $replicationFailures += [pscustomobject]@{
                Target            = $dc.HostName
                Server            = $dc.HostName
                Partner           = ''
                FirstFailureTime  = $null
                FailureCount      = $null
                LastError         = ''
                LastErrorMessage  = $_.Exception.Message
                Status            = 'Warn'
            }
        }
    }
}

if ($repadminAvailable) {
    Write-Host "Running repadmin summary..." -ForegroundColor Cyan
    $repSummary = Invoke-NativeCommand -FilePath 'repadmin.exe' -Arguments @('/replsummary')
    $rawCommands.Add([pscustomobject]@{
        Name     = 'repadmin /replsummary'
        ExitCode = $repSummary.ExitCode
        Output   = $repSummary.Output
    })
}

if (-not $SkipDcDiag -and $dcdiagAvailable -and $domainControllers.Count -gt 0) {
    Write-Host "Running dcdiag on each domain controller. This can take a while..." -ForegroundColor Cyan

    foreach ($dc in $domainControllers) {
        $diag = Invoke-NativeCommand -FilePath 'dcdiag.exe' -Arguments @("/s:$($dc.HostName)", '/q')
        $rawCommands.Add([pscustomobject]@{
            Name     = "dcdiag /s:$($dc.HostName) /q"
            ExitCode = $diag.ExitCode
            Output   = $diag.Output
        })

        $hasFailure = $diag.Output -match 'failed test|fatal|error|failed'
        $status = if ($diag.ExitCode -eq 0 -and -not $hasFailure -and [string]::IsNullOrWhiteSpace($diag.Output)) { 'Pass' } elseif ($hasFailure) { 'Fail' } else { 'Warn' }
        $dcdiagHealth += [pscustomobject]@{
            Target   = $dc.HostName
            Status   = $status
            ExitCode = $diag.ExitCode
            Message  = if ([string]::IsNullOrWhiteSpace($diag.Output)) { 'DCDiag quiet mode returned no issues.' } else { $diag.Output }
        }
    }
}
elseif ($SkipDcDiag) {
    $dcdiagHealth += [pscustomobject]@{ Target = 'All'; Status = 'Skipped'; ExitCode = $null; Message = 'Skipped by parameter.' }
}

if (-not $SkipDnsTests -and $domainControllers.Count -gt 0) {
    Write-Host "Collecting DNS health..." -ForegroundColor Cyan

    $forestDnsName = if ($forest) { $forest.Name } elseif ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { '' }
    foreach ($dc in $domainControllers) {
        $target = $dc.HostName

        if (Test-CommandExists -Name 'Resolve-DnsName') {
            try {
                $dcRecord = Resolve-DnsName -Name $target -Server $target -ErrorAction Stop
                $dnsHealth += [pscustomobject]@{
                    Target  = $target
                    Test    = 'Resolve own host record'
                    Status  = 'Pass'
                    Message = "Resolved $target using DNS server $target."
                    Data    = @($dcRecord | Select-Object -First 5 Name, Type, IPAddress, NameHost)
                }
            }
            catch {
                $dnsHealth += [pscustomobject]@{
                    Target  = $target
                    Test    = 'Resolve own host record'
                    Status  = 'Fail'
                    Message = $_.Exception.Message
                    Data    = $null
                }
            }

            if ($forestDnsName) {
                $srvName = "_ldap._tcp.dc._msdcs.$forestDnsName"
                try {
                    $srvRecord = Resolve-DnsName -Name $srvName -Type SRV -Server $target -ErrorAction Stop
                    $dnsHealth += [pscustomobject]@{
                        Target  = $target
                        Test    = 'Forest DC locator SRV'
                        Status  = 'Pass'
                        Message = "Resolved $srvName using DNS server $target."
                        Data    = @($srvRecord | Select-Object -First 10 Name, Type, NameTarget, Port, Priority, Weight)
                    }
                }
                catch {
                    $dnsHealth += [pscustomobject]@{
                        Target  = $target
                        Test    = 'Forest DC locator SRV'
                        Status  = 'Fail'
                        Message = $_.Exception.Message
                        Data    = $null
                    }
                }
            }
        }
        else {
            $dnsHealth += [pscustomobject]@{
                Target  = $target
                Test    = 'Resolve-DnsName availability'
                Status  = 'Skipped'
                Message = 'Resolve-DnsName cmdlet is not available on this server.'
                Data    = $null
            }
        }

        if ($dnsModuleResult.Status -eq 'Pass') {
            try {
                $zones = @(Get-DnsServerZone -ComputerName $target -ErrorAction Stop)
                $dnsHealth += [pscustomobject]@{
                    Target  = $target
                    Test    = 'DNS zones'
                    Status  = 'Pass'
                    Message = "DNS Server module returned $($zones.Count) zone(s)."
                    Data    = @($zones | Select-Object -First 50 ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate)
                }
            }
            catch {
                $dnsHealth += [pscustomobject]@{
                    Target  = $target
                    Test    = 'DNS zones'
                    Status  = 'Warn'
                    Message = $_.Exception.Message
                    Data    = $null
                }
            }

            try {
                $forwarders = @(Get-DnsServerForwarder -ComputerName $target -ErrorAction Stop)
                $dnsHealth += [pscustomobject]@{
                    Target  = $target
                    Test    = 'DNS forwarders'
                    Status  = 'Info'
                    Message = 'Forwarder configuration collected.'
                    Data    = $forwarders
                }
            }
            catch {
                $dnsHealth += [pscustomobject]@{
                    Target  = $target
                    Test    = 'DNS forwarders'
                    Status  = 'Warn'
                    Message = $_.Exception.Message
                    Data    = $null
                }
            }
        }
    }

    if ($dcdiagAvailable) {
        $dnsDiag = Invoke-NativeCommand -FilePath 'dcdiag.exe' -Arguments @('/test:dns', '/e', '/q')
        $rawCommands.Add([pscustomobject]@{
            Name     = 'dcdiag /test:dns /e /q'
            ExitCode = $dnsDiag.ExitCode
            Output   = $dnsDiag.Output
        })

        $dnsHealth += [pscustomobject]@{
            Target  = 'Forest'
            Test    = 'DCDiag DNS enterprise test'
            Status  = if ($dnsDiag.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($dnsDiag.Output)) { 'Pass' } elseif ($dnsDiag.Output -match 'failed|error|fatal') { 'Fail' } else { 'Warn' }
            Message = if ([string]::IsNullOrWhiteSpace($dnsDiag.Output)) { 'DCDiag DNS quiet mode returned no issues.' } else { $dnsDiag.Output }
            Data    = $null
        }
    }
}
elseif ($SkipDnsTests) {
    $dnsHealth += [pscustomobject]@{ Target = 'All'; Test = 'DNS health'; Status = 'Skipped'; Message = 'Skipped by parameter.'; Data = $null }
}

if (-not $SkipGpoTests -and $gpoModuleResult.Status -eq 'Pass' -and $domains.Count -gt 0) {
    Write-Host "Collecting Group Policy health..." -ForegroundColor Cyan

    foreach ($domainName in $domains) {
        try {
            [xml]$gpoXml = Get-GPOReport -All -Domain $domainName -ReportType Xml -ErrorAction Stop
            foreach ($gpo in $gpoXml.GPOS.GPO) {
                $computerMismatch = $false
                $userMismatch = $false
                $computerAd = $null
                $computerSysvol = $null
                $userAd = $null
                $userSysvol = $null

                if ($gpo.Computer -and $gpo.Computer.VersionDirectory -and $gpo.Computer.VersionSysvol) {
                    $computerAd = [int]$gpo.Computer.VersionDirectory
                    $computerSysvol = [int]$gpo.Computer.VersionSysvol
                    $computerMismatch = ($computerAd -ne $computerSysvol)
                }

                if ($gpo.User -and $gpo.User.VersionDirectory -and $gpo.User.VersionSysvol) {
                    $userAd = [int]$gpo.User.VersionDirectory
                    $userSysvol = [int]$gpo.User.VersionSysvol
                    $userMismatch = ($userAd -ne $userSysvol)
                }

                $linkCount = 0
                if ($gpo.LinksTo -and $gpo.LinksTo.SOMPath) {
                    $linkCount = @($gpo.LinksTo).Count
                }

                $status = if ($computerMismatch -or $userMismatch) { 'Fail' } elseif ($linkCount -eq 0) { 'Info' } else { 'Pass' }
                $message = if ($computerMismatch -or $userMismatch) {
                    'GPO AD and SYSVOL versions do not match.'
                }
                elseif ($linkCount -eq 0) {
                    'GPO has no links. This may be expected for templates or staged policies.'
                }
                else {
                    'GPO AD/SYSVOL versions match.'
                }

                $gpoId = Get-GpoIdentifierFromXml -GpoXmlNode $gpo

                $gpoHealth += [pscustomobject]@{
                    Domain                 = $domainName
                    Name                   = $gpo.Name
                    Id                     = $gpoId
                    Status                 = $status
                    GpoStatus              = $gpo.GPOStatus
                    Created                = $gpo.CreatedTime
                    Modified               = $gpo.ModifiedTime
                    ComputerVersionAD      = $computerAd
                    ComputerVersionSYSVOL  = $computerSysvol
                    UserVersionAD          = $userAd
                    UserVersionSYSVOL      = $userSysvol
                    LinkCount              = $linkCount
                    Message                = $message
                }
            }
        }
        catch {
            $gpoHealth += [pscustomobject]@{
                Domain                = $domainName
                Name                  = ''
                Id                    = ''
                Status                = 'Warn'
                GpoStatus             = ''
                Created               = $null
                Modified              = $null
                ComputerVersionAD     = $null
                ComputerVersionSYSVOL = $null
                UserVersionAD         = $null
                UserVersionSYSVOL     = $null
                LinkCount             = $null
                Message               = $_.Exception.Message
            }
        }
    }
}
elseif ($SkipGpoTests) {
    $gpoHealth += [pscustomobject]@{ Domain = 'All'; Name = 'GPO health'; Id = ''; Status = 'Skipped'; GpoStatus = ''; Created = $null; Modified = $null; ComputerVersionAD = $null; ComputerVersionSYSVOL = $null; UserVersionAD = $null; UserVersionSYSVOL = $null; LinkCount = $null; Message = 'Skipped by parameter.' }
}
elseif ($gpoModuleResult.Status -ne 'Pass') {
    $gpoHealth += [pscustomobject]@{ Domain = 'All'; Name = 'GPO health'; Id = ''; Status = 'Skipped'; GpoStatus = ''; Created = $null; Modified = $null; ComputerVersionAD = $null; ComputerVersionSYSVOL = $null; UserVersionAD = $null; UserVersionSYSVOL = $null; LinkCount = $null; Message = 'GroupPolicy module is not available.' }
}

if (-not $SkipGpoTests -and $gpoModuleResult.Status -eq 'Pass' -and $domains.Count -gt 0) {
    Write-Host "Creating GPO backups and comparing against the previous run..." -ForegroundColor Cyan

    if ([string]::IsNullOrWhiteSpace($GpoBackupRoot)) {
        $GpoBackupRoot = Join-Path -Path (Get-Location) -ChildPath 'ADHealth_GPOBackups'
    }

    $forestBackupName = Get-SafeFileName -Name ($(if ($forestInfo -and $forestInfo.Name) { $forestInfo.Name } else { 'ADForest' }))
    $runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupRunPath = Join-Path -Path $GpoBackupRoot -ChildPath "$forestBackupName`_$runStamp"

    try {
        New-Item -Path $backupRunPath -ItemType Directory -Force | Out-Null
    }
    catch {
        $gpoBackupInfo += [pscustomobject]@{
            Status          = 'Warn'
            Domain          = 'All'
            BackupPath      = $backupRunPath
            PreviousRunPath = ''
            BackupCount     = $null
            Message         = "Could not create GPO backup root. $($_.Exception.Message)"
        }
    }

    $previousRunPath = $null
    try {
        $previousRunPath = @(Get-ChildItem -Path $GpoBackupRoot -Directory -ErrorAction Stop |
            Where-Object { $_.FullName -ne $backupRunPath } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1).FullName
    }
    catch {}

    foreach ($domainName in $domains) {
        $safeDomain = Get-SafeFileName -Name $domainName
        $domainBackupPath = Join-Path -Path $backupRunPath -ChildPath $safeDomain
        $currentInventoryPath = Join-Path -Path $domainBackupPath -ChildPath 'gpo-inventory.json'
        $previousInventoryPath = if ($previousRunPath) { Join-Path -Path (Join-Path -Path $previousRunPath -ChildPath $safeDomain) -ChildPath 'gpo-inventory.json' } else { $null }
        $domainGpos = @($gpoHealth | Where-Object { $_.Domain -eq $domainName })

        try {
            New-Item -Path $domainBackupPath -ItemType Directory -Force | Out-Null
            $backupResult = @(Backup-GPO -All -Domain $domainName -Path $domainBackupPath -ErrorAction Stop)

            $healthById = @{}
            $healthByName = @{}
            foreach ($healthGpo in $domainGpos) {
                $idKey = ConvertTo-GpoIdKey -Id $healthGpo.Id
                if ($idKey) {
                    $healthById[$idKey] = $healthGpo
                }
                if ($healthGpo.Name) {
                    $healthByName[[string]$healthGpo.Name] = $healthGpo
                }
            }

            $gpoObjects = @(Get-GPO -All -Domain $domainName -ErrorAction Stop)
            $inventory = @(
                foreach ($gpoObject in $gpoObjects) {
                    $displayName = [string]$gpoObject.DisplayName
                    $idKey = ConvertTo-GpoIdKey -Id $gpoObject.Id
                    $health = if ($idKey -and $healthById.ContainsKey($idKey)) {
                        $healthById[$idKey]
                    }
                    elseif ($displayName -and $healthByName.ContainsKey($displayName)) {
                        $healthByName[$displayName]
                    }
                    else {
                        $null
                    }

                    [pscustomobject]@{
                        Domain                = $domainName
                        Name                  = $displayName
                        Id                    = ConvertTo-GpoDisplayId -Id $gpoObject.Id
                        GpoStatus             = [string]$gpoObject.GpoStatus
                        Created               = $gpoObject.CreationTime
                        Modified              = $gpoObject.ModificationTime
                        ComputerVersionAD     = if ($health) { $health.ComputerVersionAD } else { $null }
                        ComputerVersionSYSVOL = if ($health) { $health.ComputerVersionSYSVOL } else { $null }
                        UserVersionAD         = if ($health) { $health.UserVersionAD } else { $null }
                        UserVersionSYSVOL     = if ($health) { $health.UserVersionSYSVOL } else { $null }
                        LinkCount             = if ($health) { $health.LinkCount } else { $null }
                    }
                }
            )
            $inventoryJson = if ($inventory.Count -gt 0) { $inventory | ConvertTo-Json -Depth 8 } else { '[]' }
            Set-Content -Path $currentInventoryPath -Value $inventoryJson -Encoding UTF8

            if (-not (Test-Path -Path $currentInventoryPath)) {
                throw "GPO inventory file was not created at $currentInventoryPath"
            }

            $gpoBackupInfo += [pscustomobject]@{
                Status          = 'Pass'
                Domain          = $domainName
                BackupPath      = $domainBackupPath
                PreviousRunPath = if ($previousRunPath) { $previousRunPath } else { '' }
                BackupCount     = $backupResult.Count
                Message         = "Created $($backupResult.Count) GPO backup item(s). Inventory: $currentInventoryPath"
            }

            if ($previousInventoryPath -and (Test-Path -Path $previousInventoryPath)) {
                $changeCountBeforeDomain = @($gpoChangeHealth).Count
                $previousGpos = @(Get-Content -Path $previousInventoryPath -Raw | ConvertFrom-Json)
                $previousById = @{}
                $currentById = @{}
                $previousByName = @{}
                $currentByName = @{}
                $matchedPreviousIds = @{}
                $matchedPreviousNames = @{}

                foreach ($gpo in @($previousGpos | Where-Object { $_.Name -or $_.Id })) {
                    $idKey = ConvertTo-GpoIdKey -Id $gpo.Id
                    $nameKey = ConvertTo-GpoNameKey -Name $gpo.Name
                    if ($idKey -and -not $previousById.ContainsKey($idKey)) { $previousById[$idKey] = $gpo }
                    if ($nameKey -and -not $previousByName.ContainsKey($nameKey)) { $previousByName[$nameKey] = $gpo }
                }
                foreach ($gpo in @($inventory | Where-Object { $_.Name -or $_.Id })) {
                    $idKey = ConvertTo-GpoIdKey -Id $gpo.Id
                    $nameKey = ConvertTo-GpoNameKey -Name $gpo.Name
                    if ($idKey -and -not $currentById.ContainsKey($idKey)) { $currentById[$idKey] = $gpo }
                    if ($nameKey -and -not $currentByName.ContainsKey($nameKey)) { $currentByName[$nameKey] = $gpo }
                }

                foreach ($gpo in @($inventory | Where-Object { $_.Name -or $_.Id })) {
                    $id = ConvertTo-GpoIdKey -Id $gpo.Id
                    $nameKey = ConvertTo-GpoNameKey -Name $gpo.Name
                    $old = $null
                    $matchedBy = ''

                    if ($id -and $previousById.ContainsKey($id)) {
                        $old = $previousById[$id]
                        $matchedBy = 'Id'
                    }
                    elseif ($nameKey -and $previousByName.ContainsKey($nameKey)) {
                        $old = $previousByName[$nameKey]
                        $matchedBy = 'Name'
                    }

                    if ($null -eq $old) {
                        $gpoChangeHealth += [pscustomobject]@{
                            Status       = 'Info'
                            Domain       = $domainName
                            ChangeType   = 'Added'
                            GPO          = $gpo.Name
                            Id           = ConvertTo-GpoDisplayId -Id $id
                            Previous     = ''
                            Current      = "Created/first seen. Modified: $($gpo.Modified)"
                            Message      = 'GPO exists in current run but not in previous run.'
                        }
                    }
                    else {
                        $new = $gpo
                        $changes = New-Object System.Collections.Generic.List[string]
                        $oldId = ConvertTo-GpoIdKey -Id $old.Id
                        $oldNameKey = ConvertTo-GpoNameKey -Name $old.Name

                        if ($oldId) { $matchedPreviousIds[$oldId] = $true }
                        if ($oldNameKey) { $matchedPreviousNames[$oldNameKey] = $true }

                        foreach ($property in @('Name', 'GpoStatus', 'Modified', 'ComputerVersionAD', 'ComputerVersionSYSVOL', 'UserVersionAD', 'UserVersionSYSVOL', 'LinkCount')) {
                            if ([string]$old.$property -ne [string]$new.$property) {
                                $changes.Add("$property`: '$($old.$property)' -> '$($new.$property)'")
                            }
                        }

                        if ($matchedBy -eq 'Name' -and $oldId -and $id -and $oldId -ne $id) {
                            $changes.Add("Inventory ID was normalized from previous '$($old.Id)' to current '$($new.Id)'")
                        }

                        if ($changes.Count -gt 0) {
                            $gpoChangeHealth += [pscustomobject]@{
                                Status       = 'Warn'
                                Domain       = $domainName
                                ChangeType   = 'Changed'
                                GPO          = $new.Name
                                Id           = ConvertTo-GpoDisplayId -Id $id
                                Previous     = $old.Name
                                Current      = $new.Name
                                Message      = ($changes -join '; ')
                            }
                        }
                    }
                }

                foreach ($gpo in @($previousGpos | Where-Object { $_.Name -or $_.Id })) {
                    $id = ConvertTo-GpoIdKey -Id $gpo.Id
                    $nameKey = ConvertTo-GpoNameKey -Name $gpo.Name
                    $existsById = ($id -and ($currentById.ContainsKey($id) -or $matchedPreviousIds.ContainsKey($id)))
                    $existsByName = ($nameKey -and ($currentByName.ContainsKey($nameKey) -or $matchedPreviousNames.ContainsKey($nameKey)))

                    if (-not $existsById -and -not $existsByName) {
                        $gpoChangeHealth += [pscustomobject]@{
                            Status       = 'Warn'
                            Domain       = $domainName
                            ChangeType   = 'Removed'
                            GPO          = $gpo.Name
                            Id           = ConvertTo-GpoDisplayId -Id $id
                            Previous     = "Modified: $($gpo.Modified)"
                            Current      = ''
                            Message      = 'GPO existed in previous run but not in current run.'
                        }
                    }
                }

                $changeCountAfterDomain = @($gpoChangeHealth).Count
                if ($previousById.Count -eq 0 -and $currentById.Count -eq 0) {
                    $gpoChangeHealth += [pscustomobject]@{
                        Status       = 'Warn'
                        Domain       = $domainName
                        ChangeType   = 'Inventory issue'
                        GPO          = 'All'
                        Id           = ''
                        Previous     = $previousInventoryPath
                        Current      = $currentInventoryPath
                        Message      = 'Previous and current inventory files do not contain comparable GPO IDs. A fresh baseline was created; run the script again to compare.'
                    }
                }
                elseif ($changeCountAfterDomain -eq $changeCountBeforeDomain) {
                    $gpoChangeHealth += [pscustomobject]@{
                        Status       = 'Pass'
                        Domain       = $domainName
                        ChangeType   = 'No changes'
                        GPO          = 'All'
                        Id           = ''
                        Previous     = $previousInventoryPath
                        Current      = $currentInventoryPath
                        Message      = 'No GPO additions, removals, or tracked property changes were detected since the previous run.'
                    }
                }
            }
            else {
                $gpoChangeHealth += [pscustomobject]@{
                    Status       = 'Info'
                    Domain       = $domainName
                    ChangeType   = 'Baseline'
                    GPO          = 'All'
                    Id           = ''
                    Previous     = ''
                    Current      = $currentInventoryPath
                    Message      = 'No previous GPO inventory found. This run becomes the baseline for the next comparison.'
                }
            }
        }
        catch {
            $gpoBackupInfo += [pscustomobject]@{
                Status          = 'Warn'
                Domain          = $domainName
                BackupPath      = $domainBackupPath
                PreviousRunPath = if ($previousRunPath) { $previousRunPath } else { '' }
                BackupCount     = $null
                Message         = $_.Exception.Message
            }
            $gpoChangeHealth += [pscustomobject]@{
                Status       = 'Warn'
                Domain       = $domainName
                ChangeType   = 'Backup failed'
                GPO          = ''
                Id           = ''
                Previous     = ''
                Current      = ''
                Message      = $_.Exception.Message
            }
        }
    }
}

if ($IncludeEventLogs -and $domainControllers.Count -gt 0) {
    Write-Host "Collecting recent critical/error events from DC logs..." -ForegroundColor Cyan
    $since = (Get-Date).AddHours(-1 * $EventLogHours)
    $logs = @('Directory Service', 'DNS Server', 'DFS Replication', 'System')

    foreach ($dc in $domainControllers) {
        foreach ($log in $logs) {
            try {
                $events = @(Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName = $log; Level = @(1, 2); StartTime = $since } -MaxEvents 25 -ErrorAction Stop)
                $eventHealth += [pscustomobject]@{
                    Target       = $dc.HostName
                    LogName      = $log
                    Status       = if ($events.Count -gt 0) { 'Warn' } else { 'Pass' }
                    ErrorCount   = $events.Count
                    Since        = $since
                    Message      = if ($events.Count -gt 0) { "Found $($events.Count) recent critical/error event(s)." } else { 'No recent critical/error events found.' }
                    SampleEvents = @($events | Select-Object -First 10 TimeCreated, Id, ProviderName, LevelDisplayName, Message)
                }
            }
            catch {
                $eventHealth += [pscustomobject]@{
                    Target       = $dc.HostName
                    LogName      = $log
                    Status       = 'Warn'
                    ErrorCount   = $null
                    Since        = $since
                    Message      = $_.Exception.Message
                    SampleEvents = @()
                }
            }
        }
    }
}

foreach ($row in $connectivitySummary) {
    if ($row.Status -eq 'Fail') {
        Add-Recommendation -List $recommendations -Severity 'Critical' -Title "Open required ports to $($row.Target)" -Details $row.RequiredFirewallGuidance -Action 'Update host or network firewall rules so the script server can reach the listed destination ports on this DC. Also validate the Windows dynamic RPC range when service/event/DCDiag checks fail despite TCP 135 being open.'
    }
}

foreach ($row in @($replicationHealth | Where-Object { $_.Status -eq 'Fail' } | Select-Object -First 10)) {
    Add-Recommendation -List $recommendations -Severity 'Critical' -Title "Replication issue on $($row.Target)" -Details "Partner: $($row.Partner); Partition: $($row.Partition); Error: $($row.LastReplicationResultMessage)" -Action 'Review AD Sites and Services topology, DNS, RPC connectivity, and run repadmin /showrepl for the affected DC.'
}

foreach ($row in @($gpoHealth | Where-Object { $_.Status -eq 'Fail' } | Select-Object -First 10)) {
    Add-Recommendation -List $recommendations -Severity 'Warning' -Title "GPO version mismatch: $($row.Name)" -Details "Domain: $($row.Domain); computer AD/SYSVOL: $($row.ComputerVersionAD)/$($row.ComputerVersionSYSVOL); user AD/SYSVOL: $($row.UserVersionAD)/$($row.UserVersionSYSVOL)" -Action 'Check SYSVOL/DFSR replication and review this GPO in Group Policy Management Console.'
}

foreach ($row in @($dnsHealth | Where-Object { $_.Status -eq 'Fail' } | Select-Object -First 10)) {
    Add-Recommendation -List $recommendations -Severity 'Critical' -Title "DNS issue on $($row.Target)" -Details "$($row.Test): $($row.Message)" -Action 'Verify DNS service health, AD-integrated zones, DC locator SRV records, and client/server firewall access to DNS.'
}

foreach ($row in @($dcInventory | Where-Object { $_.PatchStatus -eq 'Warn' } | Select-Object -First 10)) {
    Add-Recommendation -List $recommendations -Severity 'Warning' -Title "Review patch status on $($row.Target)" -Details $row.PatchMessage -Action "Confirm Windows Update/WSUS compliance for this DC. The report warning threshold is $PatchWarningDays day(s) since the latest installed hotfix."
}

if ($domainControllers.Count -eq 0) {
    Add-Recommendation -List $recommendations -Severity 'Critical' -Title 'No domain controllers discovered' -Details 'The script could not enumerate domain controllers.' -Action 'Resolve prerequisite failures first, especially the ActiveDirectory module, DNS, and credentials.'
}

$allHealthRows = @()
$allHealthRows += $prerequisites
$allHealthRows += $findings
$allHealthRows += @($dcInventory | ForEach-Object { New-Result -Area 'DC Inventory' -Target $_.Target -Name 'Server version and patch status' -Status $_.Status -Message "$($_.OperatingSystem) $($_.Version) build $($_.BuildNumber). $($_.PatchMessage)" })
$allHealthRows += @($directoryStats | ForEach-Object { New-Result -Area 'Directory Objects' -Target $_.Domain -Name 'User and group counts' -Status $_.Status -Message $_.Message })
$allHealthRows += @($privilegedGroupStats | ForEach-Object { New-Result -Area 'Privileged Groups' -Target $_.Domain -Name $_.Group -Status $_.Status -Message $_.Message })
$allHealthRows += @($connectivitySummary | ForEach-Object { New-Result -Area 'Connectivity' -Target $_.Target -Name 'Required TCP port reachability' -Status $_.Status -Message $_.RequiredFirewallGuidance })
$allHealthRows += @($serviceHealth | ForEach-Object { New-Result -Area 'Services' -Target $_.Target -Name $_.ServiceName -Status $_.Status -Message $_.Message })
$allHealthRows += @($shareHealth | ForEach-Object { New-Result -Area 'Shares' -Target $_.Target -Name $_.Share -Status $_.Status -Message $_.Message })
$allHealthRows += @($timeHealth | ForEach-Object { New-Result -Area 'Time' -Target $_.Target -Name 'W32Time status' -Status $_.Status -Message $_.Message })
$allHealthRows += @($replicationHealth | ForEach-Object { New-Result -Area 'Replication' -Target $_.Target -Name $_.Partition -Status $_.Status -Message $_.LastReplicationResultMessage })
$allHealthRows += @($dnsHealth | ForEach-Object { New-Result -Area 'DNS' -Target $_.Target -Name $_.Test -Status $_.Status -Message $_.Message })
$allHealthRows += @($gpoHealth | ForEach-Object { New-Result -Area 'GPO' -Target $_.Domain -Name $_.Name -Status $_.Status -Message $_.Message })
$allHealthRows += @($gpoBackupInfo | ForEach-Object { New-Result -Area 'GPO Backup' -Target $_.Domain -Name 'GPO backup' -Status $_.Status -Message $_.Message })
$allHealthRows += @($gpoChangeHealth | Where-Object { $_.Status -ne 'Info' } | ForEach-Object { New-Result -Area 'GPO Changes' -Target $_.Domain -Name $_.ChangeType -Status $_.Status -Message $_.Message })
$allHealthRows += @($dcdiagHealth | ForEach-Object { New-Result -Area 'DCDiag' -Target $_.Target -Name 'DCDiag quiet mode' -Status $_.Status -Message $_.Message })
$allHealthRows += @($eventHealth | ForEach-Object { New-Result -Area 'Events' -Target $_.Target -Name $_.LogName -Status $_.Status -Message $_.Message })

$overallStatus = Join-Status -Items $allHealthRows
$completedAt = Get-Date
$totalUsers = Get-NumericSum -Items @($directoryStats) -Property 'TotalUsers'
$enabledUsers = Get-NumericSum -Items @($directoryStats) -Property 'EnabledUsers'
$disabledUsers = Get-NumericSum -Items @($directoryStats) -Property 'DisabledUsers'
$totalGroups = Get-NumericSum -Items @($directoryStats) -Property 'TotalGroups'
$domainAdminUsers = Get-NumericSum -Items @($privilegedGroupStats | Where-Object { $_.Group -eq 'Domain Admins' }) -Property 'UserCount'
$enterpriseAdminUsers = Get-NumericSum -Items @($privilegedGroupStats | Where-Object { $_.Group -eq 'Enterprise Admins' }) -Property 'UserCount'
$schemaAdminUsers = Get-NumericSum -Items @($privilegedGroupStats | Where-Object { $_.Group -eq 'Schema Admins' }) -Property 'UserCount'

$summaryCards = @(
    [pscustomobject]@{ Label = 'Overall status'; Value = $overallStatus; Status = $overallStatus; Detail = 'Worst status across all collected checks.' },
    [pscustomobject]@{ Label = 'Forest'; Value = if ($forestInfo) { $forestInfo.Name } else { 'Unknown' }; Status = if ($forestInfo) { 'Pass' } else { 'Fail' }; Detail = if ($forestInfo) { $forestInfo.ForestMode } else { 'Forest discovery failed.' } },
    [pscustomobject]@{ Label = 'Domains'; Value = $domains.Count; Status = if ($domains.Count -gt 0) { 'Pass' } else { 'Fail' }; Detail = 'Domains discovered in the forest.' },
    [pscustomobject]@{ Label = 'Domain controllers'; Value = $domainControllers.Count; Status = if ($domainControllers.Count -gt 0) { 'Pass' } else { 'Fail' }; Detail = 'DCs discovered across all domains.' },
    [pscustomobject]@{ Label = 'Users'; Value = if ($null -ne $totalUsers) { $totalUsers } else { 0 }; Status = (Join-Status -Items @($directoryStats)); Detail = "Enabled: $enabledUsers; Disabled: $disabledUsers." },
    [pscustomobject]@{ Label = 'Groups'; Value = if ($null -ne $totalGroups) { $totalGroups } else { 0 }; Status = (Join-Status -Items @($directoryStats)); Detail = 'Security, distribution, global, domain local, and universal groups counted.' },
    [pscustomobject]@{ Label = 'Domain Admin users'; Value = if ($null -ne $domainAdminUsers) { $domainAdminUsers } else { 0 }; Status = (Join-Status -Items @($privilegedGroupStats | Where-Object { $_.Group -eq 'Domain Admins' })); Detail = 'Recursive user members across all Domain Admins groups.' },
    [pscustomobject]@{ Label = 'Enterprise Admin users'; Value = if ($null -ne $enterpriseAdminUsers) { $enterpriseAdminUsers } else { 0 }; Status = (Join-Status -Items @($privilegedGroupStats | Where-Object { $_.Group -eq 'Enterprise Admins' })); Detail = 'Recursive user members in Enterprise Admins.' },
    [pscustomobject]@{ Label = 'Schema Admin users'; Value = if ($null -ne $schemaAdminUsers) { $schemaAdminUsers } else { 0 }; Status = (Join-Status -Items @($privilegedGroupStats | Where-Object { $_.Group -eq 'Schema Admins' })); Detail = 'Recursive user members in Schema Admins.' },
    [pscustomobject]@{ Label = 'Sites'; Value = $sites.Count; Status = if ($sites.Count -gt 0) { 'Pass' } else { 'Warn' }; Detail = 'AD replication sites discovered.' },
    [pscustomobject]@{ Label = 'Patch warnings'; Value = @($dcInventory | Where-Object { $_.PatchStatus -eq 'Warn' }).Count; Status = (Join-Status -Items @($dcInventory | ForEach-Object { [pscustomobject]@{ Status = $_.PatchStatus } })); Detail = "DCs older than $PatchWarningDays days since latest installed hotfix, or patch data unavailable." },
    [pscustomobject]@{ Label = 'Connectivity'; Value = @($connectivitySummary | Where-Object { $_.Status -eq 'Pass' }).Count.ToString() + '/' + $connectivitySummary.Count.ToString(); Status = (Join-Status -Items @($connectivitySummary)); Detail = 'DCs with required TCP ports reachable.' },
    [pscustomobject]@{ Label = 'Replication'; Value = @($replicationHealth | Where-Object { $_.Status -eq 'Fail' }).Count; Status = (Join-Status -Items @($replicationHealth)); Detail = 'Replication failures or non-zero last results.' },
    [pscustomobject]@{ Label = 'DNS'; Value = @($dnsHealth | Where-Object { $_.Status -eq 'Fail' }).Count; Status = (Join-Status -Items @($dnsHealth)); Detail = 'DNS checks currently failing.' },
    [pscustomobject]@{ Label = 'GPO'; Value = @($gpoHealth | Where-Object { $_.Status -eq 'Fail' }).Count; Status = (Join-Status -Items @($gpoHealth)); Detail = 'GPO AD/SYSVOL version mismatches.' },
    [pscustomobject]@{ Label = 'GPO changes'; Value = @($gpoChangeHealth | Where-Object { $_.ChangeType -in @('Added', 'Removed', 'Changed') }).Count; Status = (Join-Status -Items @($gpoChangeHealth)); Detail = 'Changes compared with the previous GPO backup inventory.' },
    [pscustomobject]@{ Label = 'Runtime'; Value = [math]::Round(($completedAt - $startedAt).TotalMinutes, 2); Status = 'Info'; Detail = 'Minutes used to collect this report.' }
)

$updateInfo = [ordered]@{
    Status           = if ($SkipUpdateCheck) { 'Skipped' } else { 'Info' }
    CurrentVersion   = $scriptVersion
    LatestVersion    = ''
    IsUpdateAvailable = $false
    RepositoryUrl    = $GitHubRepositoryUrl
    ReleaseUrl       = Convert-GitHubRepoToReleaseUrl -RepositoryUrl $GitHubRepositoryUrl
    Message          = if ($SkipUpdateCheck) { 'Update check skipped by parameter.' } else { 'No update check has run yet.' }
    CheckedAt        = (Get-Date).ToString('s')
}

if (-not $SkipUpdateCheck) {
    $apiUrl = Convert-GitHubRepoToApiUrl -RepositoryUrl $GitHubRepositoryUrl
    if ([string]::IsNullOrWhiteSpace($apiUrl)) {
        $updateInfo.Status = 'Warn'
        $updateInfo.Message = 'GitHub repository URL was not recognized. Use owner/repo or https://github.com/owner/repo.'
    }
    else {
        try {
            Write-Host "Checking GitHub for newer script release..." -ForegroundColor Cyan
            $latestRelease = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -Headers @{ 'User-Agent' = 'ADHealthDashboard' } -TimeoutSec 8 -ErrorAction Stop
            $latestVersion = if ($latestRelease.tag_name) { [string]$latestRelease.tag_name } else { [string]$latestRelease.name }
            $releaseUrl = if ($latestRelease.html_url) { [string]$latestRelease.html_url } else { Convert-GitHubRepoToReleaseUrl -RepositoryUrl $GitHubRepositoryUrl }
            $isNewer = Test-NewerVersion -CurrentVersion $scriptVersion -LatestVersion $latestVersion

            $updateInfo.Status = if ($isNewer) { 'Warn' } else { 'Pass' }
            $updateInfo.LatestVersion = $latestVersion
            $updateInfo.IsUpdateAvailable = $isNewer
            $updateInfo.ReleaseUrl = $releaseUrl
            $updateInfo.Message = if ($isNewer) { "A newer release is available: $latestVersion." } else { "This script is current. Latest release: $latestVersion." }
            $updateInfo.CheckedAt = (Get-Date).ToString('s')
        }
        catch {
            try {
                $tagsUrl = $apiUrl -replace '/releases/latest$', '/tags'
                $latestTags = @(Invoke-RestMethod -Uri $tagsUrl -UseBasicParsing -Headers @{ 'User-Agent' = 'ADHealthDashboard' } -TimeoutSec 8 -ErrorAction Stop)
                if ($latestTags.Count -gt 0 -and $latestTags[0].name) {
                    $latestVersion = [string]$latestTags[0].name
                    $releaseUrl = Convert-GitHubRepoToReleaseUrl -RepositoryUrl $GitHubRepositoryUrl
                    $isNewer = Test-NewerVersion -CurrentVersion $scriptVersion -LatestVersion $latestVersion

                    $updateInfo.Status = if ($isNewer) { 'Warn' } else { 'Pass' }
                    $updateInfo.LatestVersion = $latestVersion
                    $updateInfo.IsUpdateAvailable = $isNewer
                    $updateInfo.ReleaseUrl = $releaseUrl
                    $updateInfo.Message = if ($isNewer) { "A newer tag is available: $latestVersion." } else { "This script is current. Latest tag: $latestVersion." }
                    $updateInfo.CheckedAt = (Get-Date).ToString('s')
                }
                else {
                    $updateInfo.Status = 'Warn'
                    $updateInfo.Message = 'Could not find a GitHub release or tag to compare.'
                    $updateInfo.CheckedAt = (Get-Date).ToString('s')
                }
            }
            catch {
                $updateInfo.Status = 'Warn'
                $updateInfo.Message = "Could not check GitHub releases or tags. $($_.Exception.Message)"
                $updateInfo.CheckedAt = (Get-Date).ToString('s')
            }
        }
    }
}

$report = [ordered]@{
    Metadata = [ordered]@{
        GeneratedAt       = $completedAt.ToString('yyyy-MM-dd HH:mm:ss')
        StartedAt         = $startedAt.ToString('yyyy-MM-dd HH:mm:ss')
        RuntimeSeconds    = [math]::Round(($completedAt - $startedAt).TotalSeconds, 2)
        RunHost           = $env:COMPUTERNAME
        RunUser           = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        ScriptVersion     = $scriptVersion
    }
    OverallStatus       = $overallStatus
    UpdateInfo          = $updateInfo
    SummaryCards        = $summaryCards
    Forest              = $forestInfo
    Domains             = $domainInfo
    DomainControllers   = $domainControllers
    DcInventory         = $dcInventory
    DirectoryStats      = $directoryStats
    GroupTypeStats      = $groupTypeStats
    PrivilegedGroups    = $privilegedGroupStats
    FSMORoles           = $fsmoRoles
    Prerequisites       = $prerequisites
    ConnectivitySummary = $connectivitySummary
    ConnectivityDetails = $connectivity
    PortDefinitions     = $portDefinitions
    UdpPortNotes        = $udpPortNotes
    Services            = $serviceHealth
    Shares              = $shareHealth
    TimeHealth          = $timeHealth
    ReplicationHealth   = $replicationHealth
    ReplicationFailures = $replicationFailures
    DnsHealth           = $dnsHealth
    Sites               = $sites
    SiteLinks           = $siteLinks
    Subnets             = $subnets
    GpoHealth           = $gpoHealth
    GpoBackupInfo       = $gpoBackupInfo
    GpoChangeHealth     = $gpoChangeHealth
    DcDiag              = $dcdiagHealth
    EventHealth         = $eventHealth
    Findings            = $findings
    Recommendations     = $recommendations
    RawCommands         = $rawCommands
    AllHealthRows       = $allHealthRows
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $safeForestName = if ($forestInfo -and $forestInfo.Name) { $forestInfo.Name -replace '[^a-zA-Z0-9.-]', '_' } else { 'ADForest' }
    $OutputPath = Join-Path -Path (Get-Location) -ChildPath ("ADHealthDashboard_{0}_{1}.html" -f $safeForestName, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

$reportJson = ConvertTo-HtmlSafeJson -InputObject $report

$htmlTemplate = @'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AD Health Dashboard</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #071421;
      --panel: rgba(10, 30, 48, 0.92);
      --panel-2: rgba(13, 42, 67, 0.96);
      --text: #eef7ff;
      --muted: #8fa9bd;
      --line: rgba(118, 183, 214, 0.18);
      --green: #48e36f;
      --green-bg: rgba(72, 227, 111, 0.14);
      --red: #ff5e6b;
      --red-bg: rgba(255, 94, 107, 0.14);
      --amber: #ffce4a;
      --amber-bg: rgba(255, 206, 74, 0.15);
      --blue: #28b7ff;
      --blue-bg: rgba(40, 183, 255, 0.14);
      --cyan: #41f2ff;
      --gray-bg: rgba(156, 178, 198, 0.14);
      --shadow: 0 22px 60px rgba(0, 0, 0, 0.42);
    }
    * { box-sizing: border-box; }
    body.theme-light {
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --panel-2: #eef2f7;
      --text: #172033;
      --muted: #5d6b82;
      --line: #d9e0ea;
      --green: #198754;
      --green-bg: #e8f5ee;
      --red: #c83232;
      --red-bg: #fdecec;
      --amber: #a56400;
      --amber-bg: #fff4df;
      --blue: #2368b6;
      --blue-bg: #eaf2ff;
      --cyan: #2368b6;
      --gray-bg: #f0f2f5;
      --shadow: 0 10px 30px rgba(21, 31, 49, 0.08);
    }
    body {
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 18% -10%, rgba(40, 183, 255, 0.2), transparent 28%),
        radial-gradient(circle at 88% 4%, rgba(72, 227, 111, 0.12), transparent 24%),
        linear-gradient(145deg, #05101c 0%, #071421 46%, #0a1928 100%);
    }
    body.theme-light {
      background: #f5f7fb;
    }
    header {
      background: rgba(5, 16, 28, 0.78);
      color: #ffffff;
      padding: 24px 28px 18px;
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(16px);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    header h1 {
      margin: 0 0 8px;
      font-size: 26px;
      font-weight: 700;
      letter-spacing: 0;
    }
    .topbar {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
    }
    .theme-control {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #b8d4e7;
      font-size: 13px;
      white-space: nowrap;
    }
    .theme-select {
      border: 1px solid var(--line);
      background: rgba(10, 30, 48, 0.78);
      color: var(--text);
      border-radius: 6px;
      padding: 7px 9px;
      font-weight: 700;
    }
    body.theme-light header {
      background: #182235;
      border-bottom: 4px solid #3aa675;
      backdrop-filter: none;
    }
    body.theme-light .theme-select,
    body.theme-light .tab-button,
    body.theme-light .search,
    body.theme-light .col-filter {
      background: #ffffff;
      color: #172033;
    }
    body.theme-light footer {
      background: #ffffff;
    }
    body.theme-light .card-group {
      background: #ffffff;
    }
    body.theme-light th {
      background: #f6f8fb;
      color: #34445c;
    }
    body.theme-light .table-wrap {
      background: #ffffff;
    }
    body.theme-light tbody tr:nth-child(even) td { background: #fbfcfe; }
    body.theme-light tr:hover td { background: #edf5ff; }
    body.theme-light .pie { box-shadow: inset 0 0 0 14px #ffffff; }
    header .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 12px 24px;
      color: #b8d4e7;
      font-size: 13px;
    }
    main { padding: 22px 28px 36px; }
    footer {
      padding: 20px 28px 30px;
      color: var(--muted);
      font-size: 13px;
      border-top: 1px solid var(--line);
      background: rgba(5, 16, 28, 0.82);
    }
    .footer-grid {
      display: grid;
      grid-template-columns: 1.2fr 1fr 1fr;
      gap: 18px;
      align-items: start;
    }
    .footer-title {
      color: var(--text);
      font-weight: 750;
      margin-bottom: 6px;
    }
    .footer-line { line-height: 1.55; }
    footer a { color: var(--blue); font-weight: 700; text-decoration: none; }
    footer a:hover { text-decoration: underline; }
    .tabs {
      display: flex;
      gap: 6px;
      overflow-x: auto;
      padding-bottom: 8px;
      margin-bottom: 16px;
    }
    .tab-button {
      border: 1px solid var(--line);
      background: rgba(10, 30, 48, 0.78);
      color: var(--text);
      padding: 9px 13px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      white-space: nowrap;
    }
    .tab-button.active {
      background: linear-gradient(135deg, #0d80ff, #18c7ff);
      border-color: rgba(65, 242, 255, 0.75);
      color: #ffffff;
      box-shadow: 0 8px 24px rgba(24, 199, 255, 0.2);
    }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    .grid {
      display: grid;
      gap: 14px;
    }
    .cards {
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      margin-bottom: 18px;
    }
    .card-group {
      border: 1px solid var(--line);
      border-radius: 8px;
      margin-bottom: 18px;
      background: rgba(8, 24, 39, 0.88);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .card-group h3 {
      margin: 0;
      padding: 12px 15px;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: .04em;
      border-bottom: 1px solid var(--line);
    }
    .card-group .cards {
      padding: 14px;
      margin-bottom: 0;
      box-shadow: none;
    }
    .group-domain h3 { background: rgba(40, 183, 255, 0.12); color: var(--cyan); }
    .group-objects h3 { background: rgba(72, 227, 111, 0.11); color: var(--green); }
    .group-health h3 { background: rgba(255, 206, 74, 0.11); color: var(--amber); }
    .group-runtime h3 { background: rgba(156, 178, 198, 0.12); color: #c8d6e3; }
    .card, .section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 4px 16px rgba(21, 31, 49, 0.06);
    }
    .card { padding: 15px; min-height: 118px; }
    .card .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: .04em;
    }
    .card .value {
      margin-top: 8px;
      font-size: 27px;
      font-weight: 750;
      overflow-wrap: anywhere;
    }
    .card .detail {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.35;
      margin-top: 8px;
    }
    .section { margin-bottom: 18px; overflow: hidden; }
    .section h2 {
      margin: 0;
      padding: 14px 16px;
      font-size: 17px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-2);
    }
    .section .body { padding: 16px; }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .search {
      width: min(420px, 100%);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 11px;
      font-size: 14px;
      background: rgba(6, 18, 30, 0.9);
      color: var(--text);
    }
    .table-wrap {
      overflow: auto;
      max-width: 100%;
      max-height: 72vh;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(6, 18, 30, 0.9);
    }
    table {
      border-collapse: separate;
      border-spacing: 0;
      width: max-content;
      min-width: 100%;
      font-size: 13px;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: middle;
      white-space: nowrap;
      max-width: 420px;
    }
    th {
      background: #0d2a43;
      color: #bdeeff;
      position: sticky;
      top: 0;
      z-index: 1;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .03em;
      box-shadow: inset 0 -1px 0 var(--line);
    }
    tbody tr:nth-child(even) td { background: rgba(255, 255, 255, 0.018); }
    tr:hover td { background: rgba(40, 183, 255, 0.08); }
    td.wrap, th.wrap {
      white-space: normal;
      min-width: 280px;
      line-height: 1.4;
    }
    td.wide, th.wide { min-width: 260px; }
    td.xwide, th.xwide { min-width: 360px; }
    .col-filter {
      width: 100%;
      min-width: 110px;
      border: 1px solid #cfd8e6;
      border-radius: 5px;
      padding: 6px 7px;
      font-size: 12px;
      background: rgba(6, 18, 30, 0.9);
      color: var(--text);
      text-transform: none;
      letter-spacing: 0;
      font-weight: 500;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      min-width: 64px;
      justify-content: center;
      padding: 3px 8px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 12px;
      border: 1px solid transparent;
    }
    .status-Pass { color: var(--green); background: var(--green-bg); border-color: #b7dfc9; }
    .status-Fail { color: var(--red); background: var(--red-bg); border-color: #f1b9b9; }
    .status-Warn { color: var(--amber); background: var(--amber-bg); border-color: #f2d19a; }
    .status-Info { color: var(--blue); background: var(--blue-bg); border-color: #c1d8f6; }
    .status-Skipped { color: #596273; background: var(--gray-bg); border-color: #d5d9df; }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      background: #101827;
      color: #e9eef8;
      padding: 14px;
      border-radius: 8px;
      max-height: 420px;
      overflow: auto;
      font-size: 12px;
    }
    .note {
      color: var(--muted);
      line-height: 1.5;
      margin: 0 0 12px;
    }
    .split {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 14px;
    }
    .chart-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 14px;
    }
    .chart-card {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: var(--panel);
    }
    .chart-title {
      font-weight: 750;
      margin-bottom: 10px;
      color: var(--text);
    }
    .pie-row {
      display: flex;
      gap: 14px;
      align-items: center;
    }
    .pie {
      width: 112px;
      height: 112px;
      border-radius: 50%;
      flex: 0 0 auto;
      border: 1px solid var(--line);
      box-shadow: inset 0 0 0 14px #0a1e30;
    }
    .legend {
      display: grid;
      gap: 7px;
      color: var(--muted);
      font-size: 13px;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .swatch {
      width: 10px;
      height: 10px;
      border-radius: 3px;
      display: inline-block;
    }
    .update-banner {
      display: none;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      margin-bottom: 16px;
      padding: 13px 15px;
      border: 1px solid rgba(255, 206, 74, 0.38);
      border-radius: 8px;
      background: linear-gradient(135deg, rgba(255, 206, 74, 0.16), rgba(40, 183, 255, 0.09));
      box-shadow: 0 14px 36px rgba(0, 0, 0, 0.22);
    }
    .update-banner.show { display: flex; }
    .update-title { font-weight: 800; color: var(--amber); margin-bottom: 3px; }
    .update-message { color: #d9e9f4; font-size: 13px; }
    .update-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 6px;
      padding: 9px 12px;
      background: linear-gradient(135deg, #0d80ff, #18c7ff);
      color: #ffffff;
      text-decoration: none;
      font-weight: 800;
      white-space: nowrap;
      border: 1px solid rgba(65, 242, 255, 0.65);
    }
    @media (max-width: 720px) {
      main { padding: 16px; }
      footer { padding: 16px; }
      .footer-grid { grid-template-columns: 1fr; }
      header { padding: 18px 16px; }
      header h1 { font-size: 22px; }
      table { min-width: 660px; }
    }
  </style>
</head>
<body class="theme-light">
  <header>
    <div class="topbar">
      <div>
        <h1>Active Directory Health Dashboard</h1>
        <div class="meta" id="header-meta"></div>
      </div>
      <label class="theme-control">
        Theme
        <select class="theme-select" id="theme-select">
          <option value="theme-light">Classic</option>
          <option value="theme-dark">Dark</option>
        </select>
      </label>
    </div>
  </header>

  <main>
    <div class="update-banner" id="update-banner"></div>
    <nav class="tabs" id="tabs"></nav>
    <div id="panels"></div>
  </main>
  <footer id="report-footer">
    <div class="footer-grid">
      <div>
        <div class="footer-title">Credits</div>
        <div class="footer-line">Dashboard prepared for AD health review. Credits: <a href="https://core365.cloud" target="_blank" rel="noopener">core365.cloud</a>.</div>
      </div>
      <div>
        <div class="footer-title">Report Details</div>
        <div class="footer-line" id="footer-report-details"></div>
      </div>
      <div>
        <div class="footer-title">Disclaimer</div>
        <div class="footer-line">This report is a point-in-time operational health snapshot. Validate critical findings with native Microsoft tools before making production changes.</div>
      </div>
    </div>
  </footer>

  <script id="report-data" type="application/json">__REPORT_JSON__</script>
  <script>
    const report = JSON.parse(document.getElementById('report-data').textContent);
    const savedTheme = localStorage.getItem('adHealthTheme') || 'theme-light';
    document.body.classList.remove('theme-light', 'theme-dark');
    document.body.classList.add(savedTheme);

    const tabs = [
      ['summary', 'Summary'],
      ['directory', 'Directory Objects'],
      ['connectivity', 'Connectivity'],
      ['dcdetails', 'DC Details'],
      ['ad', 'AD Health'],
      ['replication', 'Replication'],
      ['dns', 'DNS Health'],
      ['sites', 'Sites'],
      ['gpo', 'GPO Health'],
      ['time', 'Time'],
      ['dcdiag', 'DCDiag'],
      ['raw', 'Raw Output']
    ];

    const statusRank = { Fail: 4, Warn: 3, Skipped: 2, Info: 1, Pass: 0 };

    function esc(value) {
      if (value === null || value === undefined) return '';
      return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    function statusPill(status) {
      const s = status || 'Info';
      return `<span class="pill status-${esc(s)}">${esc(s)}</span>`;
    }

    function arrayText(value) {
      if (Array.isArray(value)) {
        return value.map(item => arrayText(item)).join(' | ');
      }
      if (value && typeof value === 'object') {
        return Object.entries(value)
          .filter(([, v]) => v !== null && v !== undefined && v !== '')
          .map(([k, v]) => `${k}: ${arrayText(v)}`)
          .join('; ');
      }
      return value ?? '';
    }

    function normalizeRows(rows) {
      if (!rows) return [];
      return Array.isArray(rows) ? rows : [rows];
    }

    function table(rows, columns, searchable = true) {
      rows = normalizeRows(rows);
      const id = 'tbl_' + Math.random().toString(36).slice(2);
      const search = searchable ? `<div class="toolbar"><input class="search" data-table="${id}" placeholder="Filter all fields..." oninput="filterTable('${id}')"><span class="note">${rows.length} row(s)</span></div>` : '';
      const body = rows.map(row => {
        const tds = columns.map(col => {
          const raw = row[col.key];
          const value = col.status ? statusPill(raw) : esc(arrayText(raw));
          const cls = col.className ? ` class="${esc(col.className)}"` : '';
          return `<td${cls}>${value}</td>`;
        }).join('');
        return `<tr>${tds}</tr>`;
      }).join('');
      const head = columns.map(col => {
        const cls = col.className ? ` class="${esc(col.className)}"` : '';
        return `<th${cls}>${esc(col.label)}</th>`;
      }).join('');
      const filters = searchable ? columns.map((col, index) => {
        const cls = col.className ? ` class="${esc(col.className)}"` : '';
        return `<th${cls}><input class="col-filter" data-table="${id}" data-col="${index}" placeholder="Filter..." oninput="filterTable('${id}')"></th>`;
      }).join('') : '';
      const filterRow = searchable ? `<tr>${filters}</tr>` : '';
      return `${search}<div class="table-wrap"><table id="${id}"><thead><tr>${head}</tr>${filterRow}</thead><tbody>${body || `<tr><td colspan="${columns.length}">No data collected.</td></tr>`}</tbody></table></div>`;
    }

    window.filterTable = function(id) {
      const globalInput = document.querySelector(`input.search[data-table="${id}"]`);
      const globalNeedle = globalInput ? globalInput.value.toLowerCase() : '';
      const columnFilters = Array.from(document.querySelectorAll(`input.col-filter[data-table="${id}"]`))
        .map(input => ({ index: Number(input.dataset.col), value: input.value.toLowerCase() }))
        .filter(item => item.value);

      document.querySelectorAll(`#${id} tbody tr`).forEach(row => {
        const rowText = row.innerText.toLowerCase();
        const globalMatch = !globalNeedle || rowText.includes(globalNeedle);
        const columnMatch = columnFilters.every(filter => {
          const cell = row.children[filter.index];
          return cell && cell.innerText.toLowerCase().includes(filter.value);
        });
        row.style.display = globalMatch && columnMatch ? '' : 'none';
      });
    };

    function section(title, html) {
      return `<section class="section"><h2>${esc(title)}</h2><div class="body">${html}</div></section>`;
    }

    function cards(cards) {
      return `<div class="grid cards">${normalizeRows(cards).map(card => `
        <article class="card">
          <div class="label">${esc(card.Label)}</div>
          <div class="value">${esc(card.Value)}</div>
          <div style="margin-top:8px">${statusPill(card.Status)}</div>
          <div class="detail">${esc(card.Detail)}</div>
        </article>`).join('')}</div>`;
    }

    function cardGroup(title, labels, className) {
      const selected = normalizeRows(report.SummaryCards).filter(card => labels.includes(card.Label));
      if (!selected.length) return '';
      return `<section class="card-group ${esc(className)}"><h3>${esc(title)}</h3>${cards(selected)}</section>`;
    }

    function userPieCharts() {
      const rows = normalizeRows(report.DirectoryStats).filter(row => Number(row.TotalUsers || 0) > 0);
      if (!rows.length) return '<p class="note">No user count data was collected for charting.</p>';

      return `<div class="chart-grid">${rows.map(row => {
        const enabled = Number(row.EnabledUsers || 0);
        const disabled = Number(row.DisabledUsers || 0);
        const total = Math.max(Number(row.TotalUsers || 0), enabled + disabled);
        const enabledPct = total ? Math.round((enabled / total) * 100) : 0;
        const disabledPct = total ? 100 - enabledPct : 0;
        const gradient = `conic-gradient(var(--green) 0 ${enabledPct}%, var(--red) ${enabledPct}% 100%)`;
        return `<article class="chart-card">
          <div class="chart-title">${esc(row.Domain)}</div>
          <div class="pie-row">
            <div class="pie" style="background:${gradient}" title="Enabled ${enabledPct}%, disabled ${disabledPct}%"></div>
            <div class="legend">
              <div class="legend-item"><span class="swatch" style="background:var(--green)"></span>Enabled: ${esc(enabled)} (${enabledPct}%)</div>
              <div class="legend-item"><span class="swatch" style="background:var(--red)"></span>Disabled: ${esc(disabled)} (${disabledPct}%)</div>
              <div class="legend-item"><span class="swatch" style="background:#9aa7bb"></span>Total: ${esc(total)}</div>
            </div>
          </div>
        </article>`;
      }).join('')}</div>`;
    }

    function healthColumns(extra = []) {
      return [
        { key: 'Status', label: 'Status', status: true },
        ...extra,
        { key: 'Message', label: 'Message' }
      ];
    }

    function objectTable(obj) {
      if (!obj) return '<p class="note">No data collected.</p>';
      return table(Object.keys(obj).map(k => ({ Name: k, Value: arrayText(obj[k]) })), [
        { key: 'Name', label: 'Name' },
        { key: 'Value', label: 'Value' }
      ], false);
    }

    function renderSummary() {
      const prereqCols = healthColumns([
        { key: 'Area', label: 'Area' },
        { key: 'Target', label: 'Target' },
        { key: 'Name', label: 'Check' }
      ]);
      return cardGroup('Domain Details', ['Forest', 'Domains', 'Domain controllers', 'Sites'], 'group-domain')
        + cardGroup('Object Details', ['Users', 'Groups', 'Domain Admin users', 'Enterprise Admin users', 'Schema Admin users'], 'group-objects')
        + cardGroup('Health Overview', ['Overall status', 'Patch warnings', 'Connectivity', 'Replication', 'DNS', 'GPO', 'GPO changes'], 'group-health')
        + cardGroup('Run Details', ['Runtime'], 'group-runtime')
        + section('Forest', objectTable(report.Forest))
        + section('Domains', table(report.Domains, [
          { key: 'Name', label: 'Domain' },
          { key: 'NetBIOSName', label: 'NetBIOS' },
          { key: 'DomainMode', label: 'Mode' },
          { key: 'PDCEmulator', label: 'PDC' },
          { key: 'RIDMaster', label: 'RID' },
          { key: 'InfrastructureMaster', label: 'Infrastructure' }
        ]))
        + section('FSMO Role Holders', table(report.FSMORoles, [
          { key: 'Scope', label: 'Scope' },
          { key: 'Role', label: 'Role' },
          { key: 'Holder', label: 'Holder' }
        ]))
        + section('Directory Object Summary', table(report.DirectoryStats, [
          { key: 'Status', label: 'Status', status: true },
          { key: 'Domain', label: 'Domain' },
          { key: 'TotalUsers', label: 'Users' },
          { key: 'EnabledUsers', label: 'Enabled users' },
          { key: 'DisabledUsers', label: 'Disabled users' },
          { key: 'TotalGroups', label: 'Groups' },
          { key: 'SecurityGroups', label: 'Security groups' },
          { key: 'DistributionGroups', label: 'Distribution groups' },
          { key: 'GlobalGroups', label: 'Global groups' },
          { key: 'DomainLocalGroups', label: 'Domain local groups' },
          { key: 'UniversalGroups', label: 'Universal groups' },
          { key: 'Message', label: 'Message', className: 'wrap' }
        ]))
        + section('Privileged Groups', table(report.PrivilegedGroups, [
          { key: 'Status', label: 'Status', status: true },
          { key: 'Scope', label: 'Scope' },
          { key: 'Group', label: 'Group' },
          { key: 'Domain', label: 'Domain' },
          { key: 'MemberCount', label: 'Members' },
          { key: 'UserCount', label: 'User members' },
          { key: 'Message', label: 'Message', className: 'wrap' }
        ]))
        + section('Recommendations', table(report.Recommendations, [
          { key: 'Severity', label: 'Severity' },
          { key: 'Title', label: 'Title', className: 'wide' },
          { key: 'Details', label: 'Details', className: 'wrap' },
          { key: 'Action', label: 'Action', className: 'wrap' }
        ]))
        + section('Prerequisites', table(report.Prerequisites, prereqCols));
    }

    function renderDirectory() {
      return section('User Status Charts', userPieCharts())
      + section('Users and Groups by Domain', table(report.DirectoryStats, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Domain', label: 'Domain' },
        { key: 'TotalUsers', label: 'Users' },
        { key: 'EnabledUsers', label: 'Enabled users' },
        { key: 'DisabledUsers', label: 'Disabled users' },
        { key: 'TotalGroups', label: 'Groups' },
        { key: 'SecurityGroups', label: 'Security groups' },
        { key: 'DistributionGroups', label: 'Distribution groups' },
        { key: 'GlobalGroups', label: 'Global groups' },
        { key: 'DomainLocalGroups', label: 'Domain local groups' },
        { key: 'UniversalGroups', label: 'Universal groups' },
        { key: 'Message', label: 'Message', className: 'wrap' }
      ]))
      + section('Group Types and Scopes', table(report.GroupTypeStats, [
        { key: 'Domain', label: 'Domain' },
        { key: 'Type', label: 'Type' },
        { key: 'Scope', label: 'Scope' },
        { key: 'Count', label: 'Count' }
      ]))
      + section('Privileged Group Membership', table(report.PrivilegedGroups, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Scope', label: 'Scope' },
        { key: 'Group', label: 'Group' },
        { key: 'Name', label: 'AD group name' },
        { key: 'Domain', label: 'Domain' },
        { key: 'MemberCount', label: 'Recursive members' },
        { key: 'UserCount', label: 'Recursive user members' },
        { key: 'Message', label: 'Message', className: 'wrap' }
      ]));
    }

    function renderConnectivity() {
      return section('Required Port Summary', table(report.ConnectivitySummary, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'Domain', label: 'Domain' },
        { key: 'Site', label: 'Site' },
        { key: 'RequiredPortsOpen', label: 'Required open' },
        { key: 'BlockedRequiredPorts', label: 'Blocked required ports' },
        { key: 'BlockedRecommendedPorts', label: 'Blocked recommended ports' },
        { key: 'RequiredFirewallGuidance', label: 'Firewall guidance', className: 'wrap' }
      ]))
      + section('Port Reference', table(report.PortDefinitions, [
        { key: 'Protocol', label: 'Protocol' },
        { key: 'Port', label: 'Port' },
        { key: 'Required', label: 'Need' },
        { key: 'Purpose', label: 'Purpose' }
      ], false))
      + section('UDP and Dynamic RPC Notes', table(report.UdpPortNotes, [
        { key: 'Protocol', label: 'Protocol' },
        { key: 'Port', label: 'Port' },
        { key: 'Purpose', label: 'Purpose' }
      ], false))
      + section('Per-Port Results', table(report.ConnectivityDetails, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'Port', label: 'Port' },
        { key: 'Protocol', label: 'Protocol' },
        { key: 'Required', label: 'Need' },
        { key: 'LatencyMs', label: 'Latency ms' },
        { key: 'Purpose', label: 'Purpose', className: 'wrap' },
        { key: 'Message', label: 'Message', className: 'wrap' }
      ]));
    }

    function renderAd() {
      return section('Domain Controllers', table(report.DomainControllers, [
        { key: 'Name', label: 'Name' },
        { key: 'HostName', label: 'Host name' },
        { key: 'Domain', label: 'Domain' },
        { key: 'Site', label: 'Site' },
        { key: 'IPv4Address', label: 'IPv4' },
        { key: 'OperatingSystem', label: 'OS' },
        { key: 'IsGlobalCatalog', label: 'GC' },
        { key: 'IsReadOnly', label: 'RODC' },
        { key: 'Enabled', label: 'Enabled' },
        { key: 'OperationMasterRoles', label: 'FSMO roles' }
      ]))
      + section('Services', table(report.Services, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'ServiceName', label: 'Service' },
        { key: 'DisplayName', label: 'Display name' },
        { key: 'State', label: 'State' },
        { key: 'Message', label: 'Message' }
      ]))
      + section('SYSVOL and NETLOGON', table(report.Shares, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'Share', label: 'Share' },
        { key: 'Path', label: 'Path' },
        { key: 'Message', label: 'Message' }
      ]));
    }

    function renderDcDetails() {
      return section('DC Server Version and Patch Inventory', table(report.DcInventory, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'PatchStatus', label: 'Patch', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'Domain', label: 'Domain' },
        { key: 'DomainFunctionalLevel', label: 'Domain FL' },
        { key: 'ForestFunctionalLevel', label: 'Forest FL' },
        { key: 'Site', label: 'Site' },
        { key: 'OperatingSystem', label: 'Server version', className: 'xwide' },
        { key: 'Version', label: 'OS version' },
        { key: 'BuildNumber', label: 'Build' },
        { key: 'OSArchitecture', label: 'Architecture' },
        { key: 'ServicePack', label: 'Service pack' },
        { key: 'LatestHotFixID', label: 'Latest hotfix' },
        { key: 'LatestHotFixDate', label: 'Latest hotfix date' },
        { key: 'InstalledHotFixCount', label: 'Hotfix count' },
        { key: 'LastBootUpTime', label: 'Last boot' },
        { key: 'UptimeDays', label: 'Uptime days' },
        { key: 'InstallDate', label: 'Install date' },
        { key: 'Manufacturer', label: 'Manufacturer' },
        { key: 'Model', label: 'Model', className: 'wide' },
        { key: 'TotalMemoryGB', label: 'Memory GB' },
        { key: 'PatchMessage', label: 'Patch message', className: 'wrap' },
        { key: 'Message', label: 'Inventory message', className: 'wrap' }
      ]));
    }

    function renderReplication() {
      return section('Replication Partners', table(report.ReplicationHealth, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'Partner', label: 'Partner', className: 'xwide' },
        { key: 'Partition', label: 'Partition', className: 'xwide' },
        { key: 'LastReplicationSuccess', label: 'Last success' },
        { key: 'LastReplicationAttempt', label: 'Last attempt' },
        { key: 'ConsecutiveReplicationFailures', label: 'Failures' },
        { key: 'LastReplicationResult', label: 'Result' },
        { key: 'LastReplicationResultMessage', label: 'Message', className: 'wrap' }
      ]))
      + section('Replication Failures', table(report.ReplicationFailures, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'Partner', label: 'Partner', className: 'xwide' },
        { key: 'FirstFailureTime', label: 'First failure' },
        { key: 'FailureCount', label: 'Count' },
        { key: 'LastError', label: 'Last error' },
        { key: 'LastErrorMessage', label: 'Message', className: 'wrap' }
      ]));
    }

    function renderDns() {
      return section('DNS Checks', table(report.DnsHealth, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DNS server' },
        { key: 'Test', label: 'Test' },
        { key: 'Message', label: 'Message', className: 'wrap' },
        { key: 'Data', label: 'Data', className: 'wrap' }
      ]));
    }

    function renderSites() {
      return section('Sites', table(report.Sites, [
        { key: 'Name', label: 'Site' },
        { key: 'DcCount', label: 'DC count' },
        { key: 'Location', label: 'Location' },
        { key: 'Description', label: 'Description' },
        { key: 'WhenChanged', label: 'Changed' }
      ]))
      + section('Site Links', table(report.SiteLinks, [
        { key: 'Name', label: 'Link' },
        { key: 'Cost', label: 'Cost' },
        { key: 'ReplicationFrequencyInMinutes', label: 'Frequency minutes' },
        { key: 'SitesIncluded', label: 'Sites included' },
        { key: 'Options', label: 'Options' }
      ]))
      + section('Subnets', table(report.Subnets, [
        { key: 'Name', label: 'Subnet' },
        { key: 'Site', label: 'Site' },
        { key: 'Location', label: 'Location' },
        { key: 'Description', label: 'Description' }
      ]));
    }

    function renderGpo() {
      return section('GPO AD/SYSVOL Health', table(report.GpoHealth, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Domain', label: 'Domain' },
        { key: 'Name', label: 'GPO', className: 'xwide' },
        { key: 'GpoStatus', label: 'GPO status' },
        { key: 'ComputerVersionAD', label: 'Computer AD' },
        { key: 'ComputerVersionSYSVOL', label: 'Computer SYSVOL' },
        { key: 'UserVersionAD', label: 'User AD' },
        { key: 'UserVersionSYSVOL', label: 'User SYSVOL' },
        { key: 'LinkCount', label: 'Links' },
        { key: 'Message', label: 'Message', className: 'wrap' }
      ]))
      + section('GPO Backup Status', table(report.GpoBackupInfo, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Domain', label: 'Domain' },
        { key: 'BackupCount', label: 'Backups' },
        { key: 'BackupPath', label: 'Backup path', className: 'wrap' },
        { key: 'PreviousRunPath', label: 'Previous run', className: 'wrap' },
        { key: 'Message', label: 'Message', className: 'wrap' }
      ]))
      + section('GPO Changes Since Previous Run', table(report.GpoChangeHealth, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Domain', label: 'Domain' },
        { key: 'ChangeType', label: 'Change' },
        { key: 'GPO', label: 'GPO', className: 'xwide' },
        { key: 'Id', label: 'ID', className: 'wide' },
        { key: 'Previous', label: 'Previous', className: 'wrap' },
        { key: 'Current', label: 'Current', className: 'wrap' },
        { key: 'Message', label: 'Details', className: 'wrap' }
      ]));
    }

    function renderTime() {
      return section('Time Status', table(report.TimeHealth, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'Source', label: 'Source' },
        { key: 'Stratum', label: 'Stratum' },
        { key: 'ExitCode', label: 'Exit code' },
        { key: 'Message', label: 'Message' }
      ]));
    }

    function renderDcdiag() {
      return section('DCDiag Summary', table(report.DcDiag, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'ExitCode', label: 'Exit code' },
        { key: 'Message', label: 'Message' }
      ]))
      + section('Event Log Health', table(report.EventHealth, [
        { key: 'Status', label: 'Status', status: true },
        { key: 'Target', label: 'DC' },
        { key: 'LogName', label: 'Log' },
        { key: 'ErrorCount', label: 'Errors' },
        { key: 'Since', label: 'Since' },
        { key: 'Message', label: 'Message' },
        { key: 'SampleEvents', label: 'Sample events' }
      ]));
    }

    function renderRaw() {
      const rows = normalizeRows(report.RawCommands);
      if (!rows.length) return section('Raw Command Output', '<p class="note">No native command output was collected.</p>');
      return rows.map(row => section(`${row.Name} (exit ${row.ExitCode})`, `<pre>${esc(row.Output || '')}</pre>`)).join('');
    }

    const renderers = {
      summary: renderSummary,
      directory: renderDirectory,
      connectivity: renderConnectivity,
      dcdetails: renderDcDetails,
      ad: renderAd,
      replication: renderReplication,
      dns: renderDns,
      sites: renderSites,
      gpo: renderGpo,
      time: renderTime,
      dcdiag: renderDcdiag,
      raw: renderRaw
    };

    document.getElementById('header-meta').innerHTML = [
      `Generated: ${esc(report.Metadata.GeneratedAt)}`,
      `Run host: ${esc(report.Metadata.RunHost)}`,
      `Run user: ${esc(report.Metadata.RunUser)}`,
      `Script: v${esc(report.Metadata.ScriptVersion)}`,
      `PowerShell: ${esc(report.Metadata.PowerShellVersion)}`,
      `Overall: ${statusPill(report.OverallStatus)}`
    ].map(x => `<span>${x}</span>`).join('');

    document.getElementById('footer-report-details').innerHTML = [
      `Script version: v${esc(report.Metadata.ScriptVersion)}`,
      `Generated: ${esc(report.Metadata.GeneratedAt)}`,
      `Run host: ${esc(report.Metadata.RunHost)}`,
      `Runtime: ${esc(report.Metadata.RuntimeSeconds)} seconds`,
      `Update check: ${esc((report.UpdateInfo || {}).Status || 'Unknown')}`,
      `PowerShell: ${esc(report.Metadata.PowerShellVersion)}`
    ].map(x => `<div>${x}</div>`).join('');

    const updateBanner = document.getElementById('update-banner');
    const updateInfo = report.UpdateInfo || {};
    if (updateInfo.IsUpdateAvailable) {
      updateBanner.classList.add('show');
      updateBanner.innerHTML = `
        <div>
          <div class="update-title">New dashboard version available</div>
          <div class="update-message">${esc(updateInfo.Message)} Current: v${esc(updateInfo.CurrentVersion)}. Latest: ${esc(updateInfo.LatestVersion)}.</div>
        </div>
        <a class="update-button" href="${esc(updateInfo.ReleaseUrl || updateInfo.RepositoryUrl || '#')}" target="_blank" rel="noopener">Download from GitHub</a>`;
    }
    else if (updateInfo.Status === 'Warn') {
      updateBanner.classList.add('show');
      updateBanner.innerHTML = `
        <div>
          <div class="update-title">GitHub update check warning</div>
          <div class="update-message">${esc(updateInfo.Message)}</div>
        </div>
        <a class="update-button" href="${esc(updateInfo.ReleaseUrl || updateInfo.RepositoryUrl || '#')}" target="_blank" rel="noopener">Open GitHub</a>`;
    }

    const themeSelect = document.getElementById('theme-select');
    themeSelect.value = savedTheme;
    themeSelect.addEventListener('change', () => {
      document.body.classList.remove('theme-light', 'theme-dark');
      document.body.classList.add(themeSelect.value);
      localStorage.setItem('adHealthTheme', themeSelect.value);
    });

    const tabsEl = document.getElementById('tabs');
    const panelsEl = document.getElementById('panels');

    tabs.forEach(([id, label], index) => {
      const button = document.createElement('button');
      button.className = 'tab-button' + (index === 0 ? ' active' : '');
      button.textContent = label;
      button.onclick = () => activate(id);
      tabsEl.appendChild(button);

      const panel = document.createElement('section');
      panel.id = `panel-${id}`;
      panel.className = 'tab-panel' + (index === 0 ? ' active' : '');
      panel.innerHTML = renderers[id]();
      panelsEl.appendChild(panel);
    });

    function activate(id) {
      document.querySelectorAll('.tab-button').forEach((button, index) => {
        button.classList.toggle('active', tabs[index][0] === id);
      });
      document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === `panel-${id}`);
      });
    }
  </script>
</body>
</html>
'@

$html = $htmlTemplate.Replace('__REPORT_JSON__', $reportJson)

$outputDirectory = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}

Set-Content -Path $OutputPath -Value $html -Encoding UTF8

Write-Host "AD health dashboard saved to: $OutputPath" -ForegroundColor Green

if ($OpenReport) {
    Start-Process $OutputPath
}

[pscustomobject]@{
    OutputPath     = (Resolve-Path -Path $OutputPath).Path
    OverallStatus  = $overallStatus
    DomainCount    = $domains.Count
    DcCount        = $domainControllers.Count
    RecommendationCount = $recommendations.Count
}
