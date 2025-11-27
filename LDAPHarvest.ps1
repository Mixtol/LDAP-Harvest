<#
SYNOPSIS
    Collect computers,user, DC objects from the current Active Directory forest **and** from any
    additional forests reachable via given domain controllers, then stream each object as a
    single compressed JSON line to a Collector TCP collector with SSL. Throttled by -MaxEPS.
    * Works in **Windows PowerShell 5** and **PowerShell 7** (no parallel pipeline).
    * Requires only the **ActiveDirectory** RSAT module.
    * To get $Creds use $Creds=Get-Credential AND Then donf forgot to clear var!!!
EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\LDAPHarvest.ps1 `
        -CollectorAddress 11.62.10.1 -CollectorPort 6000 -MaxEPS 1000 `
        -ForceUnencrypted `
        -ShowPII -DebugMode `
        -AdditionalDC "dc1.example.com", "dc2.example.com" `
        -Credential $Creds
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CollectorAddress,
    [Parameter(Mandatory)]
    [int]$CollectorPort,
    [ValidateRange(1,1000)][int]$MaxEPS = 1000,
    [string[]]$AdditionalDC = @(),
    [pscredential]$Credential,
    [switch]$DebugMode,
    [switch]$ShowPII,
    [switch]$ForceUnencrypted
)

# ───────────────────────── HELPERS ──────────────────────────
function Write-DebugMsg {
    param([string]$Message)
    if ($DebugMode) { Write-Host "[DEBUG] $Message" -ForegroundColor Yellow }
}

function Convert-FileTime {
    param($fileTime)
    $maxFileTime = [DateTime]::MaxValue.ToFileTime() - 1
    if (-not $fileTime -or $fileTime -le 0 -or $fileTime -ge $maxFileTime) {
        return $fileTime
    }    
    try {
        return [DateTime]::FromFileTime($fileTime).ToString('o')
    }
    catch {
        return $fileTime
    }
}

function Protect-Pii {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [pscustomobject]$InputObject
    )

    begin {
        $sensitiveFields = @(
        'mail', 'mobile', 'mobilePhone',
        'displayName', 'name', 'cn', 'givenName', 'surname',
        'userPrincipalName', 'distinguishedName',
        'manager', 'title', 'department', 'office',
        'address', 'city',
        'mobile','phone'
    )
    }

    process {
        if (-Not $ShowPII) { 
            $obj = $InputObject.PSObject.Copy()
            $salt = $obj.forest
            foreach ($field in $sensitiveFields) {
                if ($obj.PSObject.Properties[$field] -and $null -ne $obj.$field) {
                    # $salt = [guid]::NewGuid().ToString("N").Substring(0, 8)
                    $valueToHash = "$($obj.$field)$salt"         
                    $hasher = [System.Security.Cryptography.SHA256]::Create()
                    $hashBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($valueToHash))
                    $hashedValue = [BitConverter]::ToString($hashBytes).Replace("-","").Substring(0, 16)
                    
                    $obj.$field = "$hashedValue"
                }
            }
            return $obj
        }
        else {return $InputObject}
        
    }
}

function Convert-UAC {
    param(
        [Parameter(Mandatory=$true)]
        [int]$UACValue
    )
    $UACFlags = @{
        0x0001 = "SCRIPT"
        0x0002 = "ACCOUNTDISABLE"
        0x0008 = "HOMEDIR_REQUIRED"
        0x0010 = "LOCKOUT"
        0x0020 = "PASSWD_NOTREQD"
        0x0040 = "PASSWD_CANT_CHANGE"
        0x0080 = "ENCRYPTED_TEXT_PWD_ALLOWED"
        0x0100 = "TEMP_DUPLICATE_ACCOUNT"
        0x0200 = "NORMAL_ACCOUNT"
        0x0800 = "INTERDOMAIN_TRUST_ACCOUNT"
        0x1000 = "WORKSTATION_TRUST_ACCOUNT"
        0x2000 = "SERVER_TRUST_ACCOUNT"
        0x10000 = "DONT_EXPIRE_PASSWORD"
        0x20000 = "SMARTCARD_REQUIRED"
        0x40000 = "TRUSTED_FOR_DELEGATION"
        0x80000 = "NOT_DELEGATED"
        0x100000 = "USE_DES_KEY_ONLY"
        0x200000 = "DONT_REQ_PREAUTH"
        0x400000 = "PASSWORD_EXPIRED"
        0x800000 = "TRUSTED_TO_AUTH_FOR_DELEGATION"
    }
    $result = @()
    foreach ($flag in $UACFlags.Keys) {
        if ($UACValue -band $flag) {
            $result += $UACFlags[$flag]
        }
    }
    if (-not $result) { return "NORMAL_ACCOUNT" }
    return $result -join "|"
}

function Test-ADModule {
    if (-not (Get-Module -ListAvailable ActiveDirectory)) {
        throw 'ActiveDirectory RSAT module is not installed.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}

function MakeDNSFilter {
    # FQDN to DN (corp.example.com" -> "DC=corp,DC=example,DC=com")
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    if ($DomainName -match "\.") {
        $domainParts = $DomainName.Split('.')
        $domainDN = "DC=" + ($domainParts -join ",DC=")
    }
    else {
        # For NetBIOS names (like "CORP")
        try {
            $domainInfo = Get-ADDomain -Identity $DomainName -ErrorAction Stop
            $domainDN = $domainInfo.DistinguishedName
        } 
        catch {
            throw "Failed to get DN for domain '$DomainName': $_"
        }
    }
    $filter = "$domainDN"
    return $filter
}

function Get-LastLogonFilters {
    $now    = Get-Date
    $cut3h  = $now.AddHours(-3).ToFileTime()
    $cut6h  = $now.AddHours(-6).ToFileTime()
    $cut12h = $now.AddHours(-12).ToFileTime()
    $cut3d  = $now.AddDays(-3).ToFileTime()
    $cut7d  = $now.AddDays(-7).ToFileTime()
    $cut20d = $now.AddDays(-20).ToFileTime()
    $cut60d = $now.AddDays(-60).ToFileTime()

    return @(
        @{ Name = '0-3h';    Filter = "lastLogonTimestamp -ge $cut3h" },
        @{ Name = '3-6h';   Filter = "lastLogonTimestamp -lt $cut3h -and lastLogonTimestamp -ge $cut6h" },
        @{ Name = '6-12h';   Filter = "lastLogonTimestamp -lt $cut6h -and lastLogonTimestamp -ge $cut12h" },
        @{ Name = '12h-3d';  Filter = "lastLogonTimestamp -lt $cut12h -and lastLogonTimestamp -ge $cut3d" },
        @{ Name = '3d-7d';   Filter = "lastLogonTimestamp -lt $cut3d -and lastLogonTimestamp -ge $cut7d" },
        @{ Name = '7d-20d';  Filter = "lastLogonTimestamp -lt $cut7d -and lastLogonTimestamp -ge $cut20d" },
        @{ Name = '20d-60d'; Filter = "lastLogonTimestamp -lt $cut20d -and lastLogonTimestamp -ge $cut60d" },
        @{ Name = '>60d';    Filter = "lastLogonTimestamp -lt $cut60d" }
    )
}

# ───────────────────────── Collector SOCKET ──────────────────────
function CollectorSocket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$CollectorAddress,
        [Parameter(Mandatory=$true)]
        [ValidateRange(1, 65535)]
        [int]$CollectorPort,
        [int]$TimeoutMilliseconds = 5000
    )
    Write-DebugMsg "Establishing connection to $CollectorAddress`:$CollectorPort"
    try {
        if (-not (Test-NetConnection $CollectorAddress -Port $CollectorPort -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            throw "Port $CollectorPort on $CollectorAddress is unreachable"
        }
    }
    catch {
        throw "Connection test failed: $_"
    }
    $tcp = $null
    $sslStream = $null
    try {
        Write-DebugMsg "Establishing TCP session"
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.SendTimeout = $TimeoutMilliseconds
        $tcp.ReceiveTimeout = $TimeoutMilliseconds
        $connectTask = $tcp.ConnectAsync($CollectorAddress, $CollectorPort)
        if (-not $connectTask.Wait($TimeoutMilliseconds)) {
            throw "Connection timed out after $TimeoutMilliseconds ms"
        }
        if (-not $tcp.Connected) {
            throw "Failed to establish TCP connection"
        }
        Write-DebugMsg "Trying to encript session"
        if (-not $ForceUnencrypted) {
            Write-DebugMsg "Encryption turned on"
            try {
                $sslStream = New-Object System.Net.Security.SslStream(
                    $tcp.GetStream(),
                    $false,
                    { param($s, $c, $ch, $e) $true }
                )
                $sslStream.AuthenticateAsClient(
                    $CollectorAddress,
                    $null,
                    [System.Security.Authentication.SslProtocols]::Tls12,
                    $false
                )
                $writer = New-Object System.IO.StreamWriter($sslStream, [Text.Encoding]::UTF8)
                $writer.AutoFlush = $true
                Write-Host "Secure connection established" -ForegroundColor Green
                return [PSCustomObject]@{
                    Client = $tcp
                    Stream = $sslStream
                    Writer = $writer
                    IsEncrypted = $true
                }
            }
            catch {
                Write-Warning "SSL handshake failed: $_"
                if ($null -ne $sslStream) { $sslStream.Dispose() }
                if ($tcp.Connected) { $tcp.Dispose() }
                throw "Failed to establish secure connection, try -ForceUnencrypted"
            }
        }
        # Start no encryption connection
        Write-DebugMsg "Encryption turned off"
        $writer = New-Object System.IO.StreamWriter($tcp.GetStream(), [Text.Encoding]::UTF8)
        $writer.AutoFlush = $true

        Write-Host "Using unencrypted TCP connection" -ForegroundColor Red
        return [PSCustomObject]@{
            Client = $tcp
            Stream = $tcp.GetStream()
            Writer = $writer
            IsEncrypted = $false
        }
    }
    catch {
        if ($null -ne $tcp) { $tcp.Dispose() }
        throw "Connection failed: $_"
    }
}
function Write-CollectorEvent {
    param(
        [Parameter(ValueFromPipeline)]$Item
    )
    
    process {
        if (-not $Item -or -not $socket.Writer) { return }
        
        try {
            $json = $Item | ConvertTo-Json -Compress -Depth 3
            $Socket.Writer.Write("$json`n")
            Write-DebugMsg "Sent: $json"
            Start-Sleep -Milliseconds $Delay
        }
        catch {
            Write-Warning "Failed to send data: $_"
        }
    }
}

# ──────────────────────── FOREST / DOMAINS ────────────────────────────────────
function Get-ForestDomains {
    param(
        [string]$Server # DC
    )
    $label = if ($Server) { $Server } else { '<current>' }
    Write-DebugMsg "Enumerating domains via $label"

    try {
        $params = @{
            ErrorAction = 'Stop'
        }
        if ($Server) { $params.Server = $Server }
        if ($Credential) { $params.Credential = $Credential }
        $forest = Get-ADForest @params
    } catch {
        Write-Warning "Forest unreachable via $label : $_"
        return
    }

    foreach ($d in $forest.Domains) {
        try {
            [pscustomobject]@{ Name = $d; Forest = $forest.Name }
        } catch {
            Write-Warning "Skip domain $d : $_"
        }
    }
}

# ────────────────── DOMAIN CONTROLLER ENUMERATION ──────────────────
function Get-DomainControllers {
    param(
        [string]$DomainName
    )

    Write-DebugMsg "Querying DCs in $DomainName"
    $lastActiveGC = $null
    $params = @{
        Filter = '*'
        Server = $DomainName # Here server means domain
        ErrorAction = 'Stop'
    }
    if ($Credential) { $params.Credential = $Credential }

    try {
        $allDCs = Get-ADDomainController @params
        $lastActiveGC = $null
        $lastActiveDC = $null
        
        # Process all DCs and find last active GC
        $allDCs | ForEach-Object {
            $dc = $_
            [pscustomobject]@{
                source        = 'ControllerHarvest'
                hostname      = $dc.Name.ToLower()
                fqdn          = $dc.HostName.ToLower()
                ipv4          = $dc.IPv4Address
                site          = $dc.Site
                enabled       = $dc.Enabled
                globalCatalog = $dc.IsGlobalCatalog
                os            = $dc.OperatingSystem
                osVersion     = $dc.OperatingSystemVersion
                forest        = $dc.Forest
                domainName    = if ($DomainName) { $DomainName.ToLower() } else { '' }
            } | Protect-Pii | Write-CollectorEvent

            # Сохраняем последний включенный DC на случай, если не найдем рабочий GC
            if ($dc.Enabled) {
                $lastActiveDC = $dc
            }
        }

        # Looking for DC
        foreach ($dc in $allDCs) {
            if ($dc.IsGlobalCatalog -and $dc.Enabled) {
                try {
                    # Checking 389 (LDAP) or 636 (LDAPS)
                    $port389 = Test-NetConnection -ComputerName $dc.HostName -Port 389 -ErrorAction SilentlyContinue
                    $port636 = Test-NetConnection -ComputerName $dc.HostName -Port 636 -ErrorAction SilentlyContinue
                    
                    if ($port389.TcpTestSucceeded -or $port636.TcpTestSucceeded) {
                        # Found working GC
                        Write-DebugMsg "Found avalible GC $($dc.HostName) from $DomainName"
                        return $dc
                    }
                    $lastActiveGC = $dc
                }
                catch {
                    Write-Warning "Connection test failed for GC $($dc.HostName): $_"
                }
            }
        }
        Write-Warning "Controller didnt pass TNC $($dc.HostName)"
        if ($lastActiveGC) {
            return $lastActiveGC
        }
        elseif ($lastActiveDC) {
            return $lastActiveDC
        }
        Write-Host "Active controller not found for $DomainName : $_" -ForegroundColor Red
        return $null
    }
    catch {
        Write-Host "Get-ADDomainController failed for $DomainName : $_" -ForegroundColor Red
        return $null
    }
}

# ─────────────────────── COMPUTER ENUMERATION ───────────────
function Get-DomainComputers {
    param(
        [string]$Server,
        [string]$DomainName,
        [string]$Forest,
        [string]$Filter
    )
    
    Write-DebugMsg "Querying computers in $DomainName from $Server"
    $params = @{ 
        SearchBase = MakeDNSFilter $DomainName
        ResultSetSize = $null
        ResultPageSize = 2000
        ErrorAction = 'Stop'
        Properties = 'DNSHostName','SamAccountName','operatingSystem','operatingSystemVersion',
                    'userAccountControl','sid','DistinguishedName',
                    'whenCreated','pwdLastSet','lastLogonTimestamp',
                    'IPv4Address','IPv6Address',
                    'primaryGroupID'
    }

    if ($Filter) { $params.Filter = $Filter } else { $params.Filter = '*' }
    if ($Credential) { $params.Credential = $Credential }
    if ($Server) { $params.Server = $Server }
    
    try {
        $computers = Get-ADComputer @params
        if (-not $computers) {
            Write-Warning "No computers found on $($params.SearchBase) Filter: $($params.Filter)"
            return
        }
        $computers | ForEach-Object {
            try {
                $flags = Convert-UAC -UACValue $_.userAccountControl
                
                [pscustomobject]@{
                    source             = "ComputerHarvest"
                    hostname           = if ($_.Name) { $_.Name.ToLower() } else { "" }
                    fqdn               = if ($_.DNSHostName) { $_.DNSHostName.ToLower() } else { "" }
                    ipv4               = $_.IPv4Address
                    ipv6               = $_.IPv6Address
                    sid                = $_.sid
                    domainName         = if ($DomainName) { $DomainName.ToLower() } else { "" }
                    forest             = if ($Forest) { $Forest.ToLower() } else { "" }
                    os                 = if ($_.operatingSystem) { $_.operatingSystem.ToLower() } else { "" }
                    osVersion          = if ($_.operatingSystemVersion) { $_.operatingSystemVersion.ToLower() } else { "" }
                    uac                = $_.userAccountControl
                    uacFlags           = $flags
                    distinguishedName  = $_.DistinguishedName
                    enabled            = -not ($_.userAccountControl -band 0x0002)
                    whenCreated        = $_.whenCreated.ToUniversalTime().ToString('o')
                    pwdLastSet         = Convert-FileTime $_.pwdLastSet
                    lastLogon          = Convert-FileTime $_.lastLogonTimestamp
                } | Protect-Pii | Write-CollectorEvent
            } catch {
                Write-Warning "Error processing $_ : $params"
            }
        }
    } catch {
        Write-Warning "Get-ADComputer failed for $DomainName : $_"
    }
}

# ─────────────────────── USER ENUMERATION ───────────────
function Get-DomainUsers {
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$DomainName,
        [string]$Forest,
        [string]$Filter
    )
    begin {
        Write-DebugMsg "Starting user enumeration in domain: $DomainName from $Server"
    }
    process {
        $params = @{
            SearchBase = MakeDNSFilter $DomainName
            ErrorAction = 'Stop'
            ResultSetSize = $null
            ResultPageSize = 2000
            Properties = @(
                'SamAccountName', 'UserPrincipalName',
                'DistinguishedName','CN', 'MemberOf',
                'userAccountControl', 'SID', 'Enabled',
                'whenCreated', 'Modified', 'pwdLastSet',
                'lastLogonTimestamp', 'LastBadPasswordAttempt'
            )
        }

        if ($Filter) { $params.Filter = $Filter } else { $params.Filter = '*' }
        if ($Credential) { $params.Credential = $Credential }
        if ($Server) { $params.Server = $Server }

        try {
            $users = Get-ADUser @params
            if (-not $users) {
                Write-Warning "No users found in $($params.SearchBase) Filter: $($params.Filter)"
                return
            }
            $users | ForEach-Object {
                try {
                    $flags = Convert-UAC -UACValue $_.userAccountControl
                    $memberOfNames = @()
                    if ($_.MemberOf) {
                        $memberOfNames = $_.MemberOf |
                            ForEach-Object {
                                $first = ($_ -split ',', 2)[0]
                                if ($first -like 'CN=*') { $first.Substring(3) } else { $first }
                            } |
                            Where-Object { $_ } |
                            ForEach-Object { $_.ToLowerInvariant() } |
                            Sort-Object -Unique
                    }
                    $memberOfCompact = ($memberOfNames -join '|')
                    $memberOfCount   = $memberOfNames.Count
                    [pscustomobject]@{
                        source             = 'UserHarvest'
                        domainName         = if ($DomainName) { $DomainName.ToLower() } else { $null }
                        forest             = if ($Forest) { $Forest.ToLower() } else { $null }
                        samAccountName     = if ($_.SamAccountName) { $_.SamAccountName.ToLower() } else { $null }
                        userPrincipalName  = $_.UserPrincipalName
                        distinguishedName  = $_.DistinguishedName
                        sid                = $_.SID.Value
                        uac                = $_.userAccountControl
                        uacFlags           = $flags
                        enabled            = $_.Enabled
                        passwordLastSet    = Convert-FileTime $_.pwdLastSet
                        lastLogon          = Convert-FileTime $_.lastLogonTimestamp
                        whenCreated        = $_.whenCreated.ToUniversalTime().ToString('o')
                        lastModified       = if ($_.Modified) { $_.Modified.ToString('o') } else { '' }
                        memberOf           = $memberOfCompact
                        memberOfCount      = $memberOfCount
                    } | Protect-Pii | Write-CollectorEvent
                }
                catch {
                    Write-Warning "Error processing user $($_.SID): $_"
                    Write-DebugMsg "User object: $($_ | ConvertTo-Json -Depth 3)"
                }
            }
        }
        catch {
            Write-Warning "Get-ADUser failed for $DomainName : $_"
            Write-DebugMsg "Error details: $($_.Exception.ToString())"
        }
    }

    end {
        Write-DebugMsg "Completed user enumeration in domain: $DomainName"
    }
}

# ───────────────────────────── MAIN ──────────────────────────
try {
    Test-ADModule
    $socket = CollectorSocket -CollectorAddress $CollectorAddress -CollectorPort $CollectorPort
    $Delay = [math]::Truncate(1000 / $MaxEPS)
    
    # 1. Getting all home domains
    $allDomains = @(Get-ForestDomains)
    $allControllers = @()

    # 2. Add uniq domains 
    if ($AdditionalDC -and $AdditionalDC.Count -gt 0) {
        foreach ($addDC in $AdditionalDC) {
            try {
                $newDomains = Get-ForestDomains -Server $addDC -ErrorAction Stop
                
                foreach ($domain in $newDomains) {
                    if ($domain.Name -notin $allDomains.Name) {
                        $allDomains += $domain
                    }
                }
            }
            catch {
                Write-Warning "Cannot get domains from DC: $addDC : $_"
            }
        }
    }
    # 3. Getting DC for all domains
    foreach ($domain in $allDomains) {
        try {
            $domainController = Get-DomainControllers -DomainName $domain.Name -ErrorAction Stop
            foreach ($dc in $domainController) {
                if ($dc) {
                    $allControllers += $dc
                }
            }
        }
        catch {
            Write-Host "Cannot get DC for $($domain.Name) : $_" -ForegroundColor Red
        }
    }
    # 4. Getting comps and user from 1 dc from each domain
    foreach ($dc in $allControllers) {
        try {
            # Many objects splitting by logTime optimization
            foreach ($f in Get-LastLogonFilters) {
                $params = @{
                    Server = $dc.HostName
                    DomainName = $dc.Domain
                    Forest = $dc.Forest
                    ErrorAction = 'Stop'
                    Filter = $f.Filter
                }
                # Main enrichmentd functions
                Get-DomainUsers @params
                Get-DomainComputers @params
            }
        }
        catch {
            Write-Host "Error getting data from Server=$($dc.HostName) on Domain=$($dc.Domain)" -ForegroundColor Red
        }
    }
    Write-Host "All harvest events sent" -ForegroundColor Green
}
finally {
    if ($null -ne $socket) {
        $socket.Writer.Dispose()
        $socket.Stream.Dispose()
        $socket.Client.Dispose()
    }
}
