param(
    [ValidateSet("probe", "drain", "preflight", "resync", "stage-summary", "root-ssh", "sysinfo", "wifi-status", "wifi-scan", "wifi-connect", "provision-wifi")]
    [string]$Action = "preflight",

    [string]$ProbeFile = "hid_probe.json",
    [string]$VendorId = "046D",
    [string]$ProductId = "C129",
    [int]$TimeoutMs = 5000,
    [int]$RetryCount = 2,
    [int]$RetryDelayMs = 250,
    [int]$DrainReports = 32,
    [int]$DrainWaitMs = 40,
    [int]$ResyncAttempts = 6,
    [switch]$RawOutput,
    [switch]$NoDrain,
    [switch]$LooseResponseMatch,
    [switch]$WriteProbe,
    [switch]$SkipPreflight,

    [string]$PublicKeyFile = "keys\harmony_root_ed25519.pub",
    [string]$PrivateKeyFile = "keys\harmony_root_ed25519",
    [string]$HubIp = "",
    [switch]$Reboot,

    [string]$Ssid = "",
    [string]$WifiPassword = "",
    [string]$Encryption = "WPA2-PSK",
    [switch]$NoSave,
    [switch]$ShowSsids,
    [switch]$WaitForLan,
    [int]$LanPort = 8088,
    [int]$LanWaitSeconds = 90,

    [string]$PackageRoot = ".",
    [int]$ChunkSize = 8000
)

$ErrorActionPreference = "Stop"
$script:NextCommandId = Get-Random -Minimum 100000 -Maximum 900000

function Resolve-LocalPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $PSScriptRoot $Path)
}

function ConvertTo-HexString {
    param($Bytes, [int]$Length = -1)
    if (-not $Bytes) { return "" }
    if ($Bytes -is [byte[]]) {
        [byte[]]$byteArray = $Bytes
    } else {
        $byteList = New-Object System.Collections.Generic.List[byte]
        foreach ($item in @($Bytes)) {
            if ($item -is [byte[]]) {
                foreach ($b in $item) {
                    $byteList.Add([byte]$b)
                }
            } else {
                $byteList.Add([byte]$item)
            }
        }
        [byte[]]$byteArray = $byteList.ToArray()
    }
    if ($Length -lt 0 -or $Length -gt $byteArray.Length) {
        $Length = $byteArray.Length
    }
    if ($Length -le 0) { return "" }
    return (($byteArray[0..($Length - 1)] | ForEach-Object { $_.ToString("X2") }) -join " ")
}

function Get-ByteListArray {
    param($List)
    if (-not $List -or $List.Count -eq 0) {
        return ,(New-Object byte[] 0)
    }
    return ,[byte[]]$List.ToArray()
}

function Read-Number {
    param([byte[]]$Bytes, [int]$Offset, [int]$Length)
    $value = 0
    for ($i = 0; $i -lt $Length; $i++) {
        $value = ($value -shl 8) -bor $Bytes[$Offset + $i]
    }
    return $value
}

function Decode-Ltcp {
    param([byte[]]$Bytes)

    $result = [ordered]@{
        Complete = $false
        Error = $null
        LeadingDiscarded = 0
        Service = $null
        Type = $null
        RequestId = $null
        IsResponse = $false
        PacketCount = $null
        PayloadLength = 0
        Payload = ""
    }

    $start = [Array]::IndexOf($Bytes, [byte]0xff)
    if ($start -lt 0) {
        $result.Error = "Need more data for LTCP primary header."
        return [pscustomobject]$result
    }
    if ($start -gt 0) {
        $result.LeadingDiscarded = $start
        $trimmed = New-Object byte[] ($Bytes.Length - $start)
        [Array]::Copy($Bytes, $start, $trimmed, 0, $trimmed.Length)
        $Bytes = $trimmed
    }

    if ($Bytes.Length -lt 4) {
        $result.Error = "Need more data for LTCP primary header."
        return [pscustomobject]$result
    }
    if ($Bytes[0] -ne 0xff) {
        $result.Error = ("Invalid LTCP service byte 0x{0:X2}." -f $Bytes[0])
        return [pscustomobject]$result
    }

    $pos = 0
    $result.Service = $Bytes[$pos++]
    $result.Type = $Bytes[$pos++]
    $result.RequestId = $Bytes[$pos++]
    $result.IsResponse = (($result.RequestId -band 0x80) -eq 0x80)
    $paramCount = $Bytes[$pos++] -band 0x3f
    $packets = 0

    for ($p = 0; $p -lt $paramCount; $p++) {
        if ($pos -ge $Bytes.Length) {
            $result.Error = "Need more data for LTCP parameter."
            return [pscustomobject]$result
        }
        $tag = $Bytes[$pos++]
        $len = $tag -band 0x3f
        if ($len -eq 0) {
            while ($pos -lt $Bytes.Length -and $Bytes[$pos] -ne 0) {
                $pos++
            }
            if ($pos -ge $Bytes.Length) {
                $result.Error = "Need more data for LTCP string parameter."
                return [pscustomobject]$result
            }
            $pos++
        } else {
            if ($pos + $len -gt $Bytes.Length) {
                $result.Error = "Need more data for LTCP numeric parameter."
                return [pscustomobject]$result
            }
            $packets = Read-Number -Bytes $Bytes -Offset $pos -Length $len
            $pos += $len
        }
    }
    $result.PacketCount = $packets

    $remaining = $packets - 1
    $payload = New-Object System.Collections.Generic.List[byte]
    while ($remaining -gt 0) {
        while ($pos -lt $Bytes.Length -and $Bytes[$pos] -eq 0) {
            $pos++
        }
        if ($pos + 2 -gt $Bytes.Length) {
            $result.Error = "Need more data for LTCP secondary header."
            return [pscustomobject]$result
        }
        $null = $Bytes[$pos++]
        $lenByte = $Bytes[$pos++]
        if (($lenByte -band 0x40) -eq 0x40) {
            if ($pos -ge $Bytes.Length) {
                $result.Error = "Need more data for LTCP long secondary length."
                return [pscustomobject]$result
            }
            $chunkLen = (($lenByte -band 0x3f) -shl 8) -bor $Bytes[$pos++]
        } else {
            $chunkLen = $lenByte -band 0x3f
        }
        if ($pos + $chunkLen -gt $Bytes.Length) {
            $result.Error = "Need more data for LTCP secondary payload."
            return [pscustomobject]$result
        }
        for ($i = 0; $i -lt $chunkLen; $i++) {
            $payload.Add($Bytes[$pos + $i])
        }
        $pos += $chunkLen
        $remaining--
    }

    $payloadBytes = $payload.ToArray()
    $result.Complete = $true
    $result.Error = $null
    $result.PayloadLength = $payloadBytes.Length
    $result.Payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
    return [pscustomobject]$result
}

function Copy-ByteSlice {
    param([byte[]]$Bytes, [int]$Offset)
    if (-not $Bytes -or $Offset -ge $Bytes.Length) {
        return ,([byte[]]@())
    }
    $slice = New-Object byte[] ($Bytes.Length - $Offset)
    [Array]::Copy($Bytes, $Offset, $slice, 0, $slice.Length)
    return ,$slice
}

function ConvertFrom-JsonPayload {
    param([string]$Payload)
    if ([string]::IsNullOrWhiteSpace($Payload)) {
        return $null
    }
    try {
        return ($Payload | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Get-LtcpCandidates {
    param([byte[]]$Bytes)

    $candidates = New-Object System.Collections.Generic.List[object]
    if (-not $Bytes -or $Bytes.Length -eq 0) {
        return ,$candidates.ToArray()
    }

    for ($offset = 0; $offset -lt $Bytes.Length; $offset++) {
        if ($Bytes[$offset] -ne 0xff) {
            continue
        }
        $decode = Decode-Ltcp -Bytes (Copy-ByteSlice -Bytes $Bytes -Offset $offset)
        $payloadObject = ConvertFrom-JsonPayload -Payload $decode.Payload
        $payloadId = $null
        $code = $null
        if ($payloadObject) {
            if ($payloadObject.PSObject.Properties.Name -contains "id") {
                $payloadId = [string]$payloadObject.id
            }
            if ($payloadObject.PSObject.Properties.Name -contains "code") {
                $code = [string]$payloadObject.code
            }
        }
        $candidates.Add([pscustomobject]@{
            Offset = $offset
            Complete = $decode.Complete
            Error = $decode.Error
            PayloadId = $payloadId
            Code = $code
            Decode = $decode
            PayloadObject = $payloadObject
        })
    }
    return ,$candidates.ToArray()
}

function Select-LtcpCandidate {
    param(
        [object[]]$Candidates,
        [int]$ExpectedPayloadId,
        [bool]$AllowLoose = $false
    )

    if (-not $Candidates -or $Candidates.Count -eq 0) {
        return $null
    }

    $expected = [string]$ExpectedPayloadId
    $matchingComplete = @($Candidates | Where-Object { $_.Complete -and $_.PayloadId -eq $expected })
    if ($matchingComplete.Count -gt 0) {
        return ($matchingComplete | Select-Object -Last 1)
    }

    if ($AllowLoose) {
        $complete = @($Candidates | Where-Object { $_.Complete })
        if ($complete.Count -gt 0) {
            return ($complete | Select-Object -Last 1)
        }
    }

    $matchingAny = @($Candidates | Where-Object { $_.PayloadId -eq $expected })
    if ($matchingAny.Count -gt 0) {
        return ($matchingAny | Select-Object -Last 1)
    }

    return ($Candidates | Select-Object -Last 1)
}

function Test-LtcpCandidateMatch {
    param(
        $Candidate,
        [int]$ExpectedPayloadId,
        [bool]$AllowLoose = $false
    )
    if (-not $Candidate -or -not $Candidate.Complete) {
        return $false
    }
    if ($Candidate.PayloadId -eq [string]$ExpectedPayloadId) {
        return $true
    }
    return [bool]$AllowLoose
}

function New-LtcpFrames {
    param([string]$Json)

    $payload = [System.Text.Encoding]::ASCII.GetBytes($Json)
    if ($payload.Length -gt 16383) {
        throw "Payload is too large for one LTCP secondary packet ($($payload.Length) bytes). Lower -ChunkSize."
    }

    $stream = New-Object System.Collections.Generic.List[byte]
    [byte[]]$primary = 0xff, 0x08, 0x00, 0x01, 0x01, 0x02
    $stream.AddRange($primary)
    $stream.Add(0x01)

    if ($payload.Length -gt 63) {
        $stream.Add([byte](0x80 -bor 0x40 -bor (($payload.Length -shr 8) -band 0x3f)))
        $stream.Add([byte]($payload.Length -band 0xff))
    } else {
        $stream.Add([byte](0x80 -bor $payload.Length))
    }
    $stream.AddRange($payload)

    $frames = New-Object System.Collections.Generic.List[byte[]]
    $offset = 0
    while ($offset -lt $stream.Count) {
        $frame = New-Object byte[] 64
        $used = [Math]::Min(64, $stream.Count - $offset)
        for ($i = 0; $i -lt $used; $i++) {
            $frame[$i] = $stream[$offset + $i]
        }
        $frames.Add($frame)
        $offset += $used
    }
    return ,$frames.ToArray()
}

function New-CommandJson {
    param([string]$CommandName, $CommandData, [int]$CommandTimeout = 5)
    $id = $script:NextCommandId
    $obj = [ordered]@{
        id = $id
        cmd = $CommandName
        data = $CommandData
        timeout = $CommandTimeout
    }
    $script:NextCommandId++
    return [pscustomobject]@{
        Id = $id
        Json = ($obj | ConvertTo-Json -Compress -Depth 50)
    }
}

function Invoke-HidProbe {
    $probeScript = Resolve-LocalPath "harmony_usb_hid_probe.ps1"
    if (-not (Test-Path $probeScript)) {
        throw "Missing HID probe script: $probeScript"
    }
    & $probeScript -VendorId $VendorId -ProductId $ProductId -OutFile (Resolve-LocalPath $ProbeFile)
}

function Ensure-HidProbe {
    $path = Resolve-LocalPath $ProbeFile
    if (-not (Test-Path $path)) {
        Invoke-HidProbe
    }
}

function Get-HidDevice {
    Ensure-HidProbe
    $path = Resolve-LocalPath $ProbeFile
    $probe = @(Get-Content -Raw -Path $path | ConvertFrom-Json)
    $device = $probe | Where-Object { $_.DevicePath } | Select-Object -First 1
    if (-not $device) {
        throw "No HID device path found in $path. Run -Action probe, then reconnect the hub if needed."
    }
    return $device
}

function Clear-HidInputQueue {
    param(
        [string]$DevicePath,
        [int]$InputReportLength,
        [int]$MaxReports = $DrainReports,
        [int]$WaitMs = $DrainWaitMs
    )

    $stream = $null
    $drained = New-Object System.Collections.Generic.List[object]
    try {
        $stream = [System.IO.File]::Open($DevicePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
        for ($n = 0; $n -lt $MaxReports; $n++) {
            $buffer = New-Object byte[] $InputReportLength
            $async = $stream.BeginRead($buffer, 0, $buffer.Length, $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne($WaitMs)) {
                break
            }
            $read = $stream.EndRead($async)
            if ($read -le 0) {
                break
            }
            $drained.Add([pscustomobject]@{
                Read = $read
                Hex = ConvertTo-HexString -Bytes $buffer -Length ([Math]::Min($read, 24))
            })
        }
    } catch {
        # Draining is best effort. The real command path below reports hard errors.
    } finally {
        if ($stream) {
            $stream.Close()
            $stream.Dispose()
        }
    }
    return [pscustomobject]@{
        Reports = $drained.Count
        Samples = @($drained | Select-Object -First 4)
    }
}

function Invoke-HarmonyUsbCommand {
    param(
        [string]$CommandName,
        $CommandData = "",
        [int]$ReadTimeoutMs = $TimeoutMs
    )

    $device = Get-HidDevice
    $devicePath = [string]$device.DevicePath
    $inputReportLength = [int]$device.InputReportByteLength
    $outputReportLength = [int]$device.OutputReportByteLength
    if ($inputReportLength -le 0) { $inputReportLength = 65 }
    if ($outputReportLength -le 0) { $outputReportLength = 65 }
    if ($outputReportLength -ne 65) {
        throw "Unexpected output report length $outputReportLength; expected 65."
    }

    $attempts = [Math]::Max(1, $RetryCount + 1)
    $lastResponse = $null

    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        $drainResult = $null
        if (-not $NoDrain) {
            $drainResult = Clear-HidInputQueue -DevicePath $devicePath -InputReportLength $inputReportLength
        }

        $request = New-CommandJson -CommandName $CommandName -CommandData $CommandData
        $frames = New-LtcpFrames -Json $request.Json
        $rawResponse = New-Object System.Collections.Generic.List[byte]
        $readReports = New-Object System.Collections.Generic.List[object]
        $candidateDecodes = @()
        $selectedCandidate = $null
        $stream = $null

        try {
            $stream = [System.IO.File]::Open($devicePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)

            foreach ($frame in $frames) {
                $report = New-Object byte[] $outputReportLength
                $report[0] = 0
                [Array]::Copy($frame, 0, $report, 1, 64)
                $stream.Write($report, 0, $report.Length)
                $stream.Flush()
            }

            $deadline = [DateTime]::UtcNow.AddMilliseconds($ReadTimeoutMs)
            while ([DateTime]::UtcNow -lt $deadline) {
                $buffer = New-Object byte[] $inputReportLength
                $async = $stream.BeginRead($buffer, 0, $buffer.Length, $null, $null)
                $remaining = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
                if (-not $async.AsyncWaitHandle.WaitOne($remaining)) {
                    break
                }
                $read = $stream.EndRead($async)
                if ($read -le 0) {
                    break
                }
                $readReports.Add([pscustomobject]@{
                    BytesRead = $read
                    Hex = ConvertTo-HexString -Bytes $buffer -Length $read
                })
                $payloadLen = [Math]::Min(64, $read - 1)
                for ($i = 0; $i -lt $payloadLen; $i++) {
                    $rawResponse.Add($buffer[$i + 1])
                }
                $rawBytes = Get-ByteListArray -List $rawResponse
                $candidateDecodes = Get-LtcpCandidates -Bytes $rawBytes
                $selectedCandidate = Select-LtcpCandidate -Candidates $candidateDecodes -ExpectedPayloadId $request.Id -AllowLoose ([bool]$LooseResponseMatch)
                if (Test-LtcpCandidateMatch -Candidate $selectedCandidate -ExpectedPayloadId $request.Id -AllowLoose ([bool]$LooseResponseMatch)) {
                    break
                }
            }
        } finally {
            if ($stream) {
                $stream.Close()
                $stream.Dispose()
            }
        }

        if (-not $selectedCandidate) {
            $rawBytes = Get-ByteListArray -List $rawResponse
            $candidateDecodes = Get-LtcpCandidates -Bytes $rawBytes
            $selectedCandidate = Select-LtcpCandidate -Candidates $candidateDecodes -ExpectedPayloadId $request.Id -AllowLoose ([bool]$LooseResponseMatch)
        }

        $rawBytes = Get-ByteListArray -List $rawResponse
        $decode = $null
        $payloadObject = $null
        if ($selectedCandidate) {
            $decode = $selectedCandidate.Decode
            $payloadObject = $selectedCandidate.PayloadObject
        } else {
            $decode = Decode-Ltcp -Bytes $rawBytes
            $payloadObject = ConvertFrom-JsonPayload -Payload $decode.Payload
        }

        $matched = Test-LtcpCandidateMatch -Candidate $selectedCandidate -ExpectedPayloadId $request.Id -AllowLoose ([bool]$LooseResponseMatch)
        $rawHex = ""
        if ($rawResponse.Count -gt 0) {
            $rawHex = ConvertTo-HexString -Bytes $rawBytes
        }
        $readReportArray = @($readReports | ForEach-Object { $_ })
        $lastResponse = [pscustomobject]@{
            DevicePath = $devicePath
            Command = $CommandName
            AppRequestId = $request.Id
            Attempt = $attempt
            Attempts = $attempts
            MatchedResponse = $matched
            Drain = $drainResult
            RequestJson = $request.Json
            FramesWritten = $frames.Count
            RawResponseLength = $rawResponse.Count
            RawResponseHex = $rawHex
            ReadReports = $readReportArray
            Decode = $decode
            PayloadObject = $payloadObject
            CandidateDecodes = @($candidateDecodes | ForEach-Object {
                [pscustomobject]@{
                    Offset = $_.Offset
                    Complete = $_.Complete
                    Error = $_.Error
                    PayloadId = $_.PayloadId
                    Code = $_.Code
                    PayloadLength = $_.Decode.PayloadLength
                }
            })
        }

        if ($matched) {
            return $lastResponse
        }
        if ($attempt -lt $attempts -and $RetryDelayMs -gt 0) {
            Start-Sleep -Milliseconds $RetryDelayMs
        }
    }

    return $lastResponse
}

function Get-HarmonyResponseCode {
    param($Response)
    if ($Response.PayloadObject -and ($Response.PayloadObject.PSObject.Properties.Name -contains "code")) {
        return [string]$Response.PayloadObject.code
    }
    return ""
}

function Assert-HarmonyOk {
    param($Response, [string]$What)
    $code = Get-HarmonyResponseCode $Response
    if ($code -ne "200") {
        $payload = if ($Response -and $Response.Decode) { $Response.Decode.Payload } else { "" }
        $complete = if ($Response -and $Response.Decode) { $Response.Decode.Complete } else { $false }
        $errorText = if ($Response -and $Response.Decode) { $Response.Decode.Error } else { "no decode" }
        $attemptText = if ($Response) { "$($Response.Attempt)/$($Response.Attempts)" } else { "none" }
        throw "$What failed with code '$code' (attempt $attemptText, complete=$complete, error=$errorText): $payload"
    }
}

function Invoke-JsonGet {
    param([string]$Path, [string]$File)
    return Invoke-HarmonyUsbCommand -CommandName "connect.jsonfiletransfer?get" -CommandData @{path = $Path; file = $File}
}

function Invoke-JsonPut {
    param([string]$Path, [string]$File, $Content)
    return Invoke-HarmonyUsbCommand -CommandName "connect.jsonfiletransfer?put" -CommandData @{path = $Path; file = $File; content = $Content}
}

function Invoke-LogPut {
    param([string]$FileName, [string]$Body)
    return Invoke-HarmonyUsbCommand -CommandName "harmony.log?put" -CommandData @{resource = @(@{fileName = $FileName; data = $Body})}
}

function Write-CompactJson {
    param($Object, [int]$Depth = 50)
    $Object | ConvertTo-Json -Depth $Depth
}

function Write-HarmonyResponse {
    param($Response)
    if ($RawOutput -or -not $Response.PayloadObject) {
        Write-CompactJson ([ordered]@{
            command = $Response.Command
            appRequestId = $Response.AppRequestId
            attempt = $Response.Attempt
            attempts = $Response.Attempts
            matchedResponse = $Response.MatchedResponse
            drain = $Response.Drain
            complete = $Response.Decode.Complete
            error = $Response.Decode.Error
            payloadLength = $Response.Decode.PayloadLength
            payload = $Response.Decode.Payload
            rawResponseLength = $Response.RawResponseLength
            rawResponseHex = $Response.RawResponseHex
            readReports = $Response.ReadReports
            candidates = $Response.CandidateDecodes
        })
        return
    }
    Write-CompactJson $Response.PayloadObject
}

function ConvertTo-RedactedObject {
    param($Object, [bool]$ShowSsids = $false)

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in $Object.Keys) {
            $out[[string]$key] = ConvertTo-RedactedNamedValue -Name ([string]$key) -Value $Object[$key] -ShowSsids $ShowSsids
        }
        return $out
    }

    if ($Object -is [pscustomobject]) {
        $out = [ordered]@{}
        foreach ($prop in $Object.PSObject.Properties) {
            $out[$prop.Name] = ConvertTo-RedactedNamedValue -Name $prop.Name -Value $prop.Value -ShowSsids $ShowSsids
        }
        return $out
    }

    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Object) {
            $items.Add((ConvertTo-RedactedObject -Object $item -ShowSsids $ShowSsids))
        }
        return ,$items.ToArray()
    }

    return $Object
}

function ConvertTo-RedactedNamedValue {
    param([string]$Name, $Value, [bool]$ShowSsids = $false)

    $low = $Name.ToLowerInvariant()
    if ($low -in @("password", "passphrase", "psk", "key")) {
        return "<redacted>"
    }
    if ($low -eq "ssid" -and -not $ShowSsids) {
        return "<ssid>"
    }
    return ConvertTo-RedactedObject -Object $Value -ShowSsids $ShowSsids
}

function Write-RedactedHarmonyResponse {
    param($Response, [bool]$ShowSsids = $false)

    $payload = ConvertTo-RedactedObject -Object $Response.PayloadObject -ShowSsids $ShowSsids
    if ($RawOutput -or -not $Response.PayloadObject) {
        Write-CompactJson ([ordered]@{
            command = $Response.Command
            appRequestId = $Response.AppRequestId
            attempt = $Response.Attempt
            attempts = $Response.Attempts
            matchedResponse = $Response.MatchedResponse
            drain = $Response.Drain
            complete = $Response.Decode.Complete
            error = $Response.Decode.Error
            payloadLength = $Response.Decode.PayloadLength
            payload = $payload
            rawResponseLength = $Response.RawResponseLength
            readReports = $Response.ReadReports
            candidates = $Response.CandidateDecodes
        })
        return
    }

    Write-CompactJson $payload
}

function Get-FileMd5 {
    param([byte[]]$Bytes)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        return (($md5.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $md5.Dispose()
    }
}

function Add-StageFile {
    param(
        [System.Collections.Generic.List[object]]$Files,
        [string]$Source,
        [string]$RemotePath,
        [string]$Mode,
        [string]$Id
    )
    $sourcePath = Resolve-LocalPath $Source
    if (-not (Test-Path $sourcePath)) {
        throw "Missing runtime file: $sourcePath"
    }
    $bytes = [System.IO.File]::ReadAllBytes($sourcePath)
    $Files.Add([pscustomobject]@{
        id = $Id
        source = $sourcePath
        path = $RemotePath
        mode = $Mode
        bytes = $bytes.Length
        md5 = Get-FileMd5 -Bytes $bytes
        data = [Convert]::ToBase64String($bytes)
    })
}

function Add-StageBytes {
    param(
        [System.Collections.Generic.List[object]]$Files,
        [byte[]]$Bytes,
        [string]$RemotePath,
        [string]$Mode,
        [string]$Id,
        [string]$Source = "<generated>"
    )
    $Files.Add([pscustomobject]@{
        id = $Id
        source = $Source
        path = $RemotePath
        mode = $Mode
        bytes = $Bytes.Length
        md5 = Get-FileMd5 -Bytes $Bytes
        data = [Convert]::ToBase64String($Bytes)
    })
}

function Protect-PrivateKeyFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $null = & icacls $Path /inheritance:r /grant:r "${identity}:F" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not tighten private key ACLs automatically. If ssh later rejects the key, restrict this file to your Windows user: $Path"
        }
    } catch {
        Write-Warning "Could not tighten private key ACLs automatically. If ssh later rejects the key, restrict this file to your Windows user: $Path"
    }
}

function Ensure-SshKeyPair {
    $pubPath = Resolve-LocalPath $PublicKeyFile
    $privPath = Resolve-LocalPath $PrivateKeyFile
    $keyDir = Split-Path -Parent $privPath
    if ($keyDir -and -not (Test-Path -LiteralPath $keyDir)) {
        New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
    }

    $pubExists = Test-Path -LiteralPath $pubPath
    $privExists = Test-Path -LiteralPath $privPath
    if ($pubExists) {
        if ($privExists) {
            Protect-PrivateKeyFile -Path $privPath
        }
        return
    }

    $sshKeygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $sshKeygen) {
        throw "No public key was found and ssh-keygen is not available. Install Windows OpenSSH Client or pass -PublicKeyFile with an existing .pub key."
    }

    if ($privExists) {
        throw "Private key exists but public key is missing: $privPath. Restore the .pub file or choose another -PrivateKeyFile/-PublicKeyFile."
    }

    Write-Host "Generating a local SSH keypair for this hub..."
    & $sshKeygen.Source -t ed25519 -f $privPath -N "" -C "harmony-root-usb" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "ssh-keygen failed."
    }
    Protect-PrivateKeyFile -Path $privPath
}

function New-OwnedRuntimeManifest {
    $files = New-Object System.Collections.Generic.List[object]
    $root = Resolve-LocalPath $PackageRoot
    $publicKey = Resolve-LocalPath $PublicKeyFile
    $dropbearmulti = Join-Path $root "dropbearmulti"

    Add-StageFile $files $dropbearmulti "/data/rootssh/bin/dropbearmulti" "755" "f001"
    Add-StageFile $files $publicKey "/home/root/.ssh/authorized_keys" "600" "f002"
    Add-StageBytes $files ([System.Text.Encoding]::UTF8.GetBytes("#!/bin/sh`nexec /data/rootssh/bin/dropbear -s -g -K 300 `"`$@`"`n")) "/usr/sbin/dropbear" "755" "f003" "dropbear-wrapper"
    Add-StageBytes $files ([System.Text.Encoding]::UTF8.GetBytes("#!/bin/sh`nexec /data/rootssh/bin/dropbearkey `"`$@`"`n")) "/usr/sbin/dropbearkey" "755" "f004" "dropbearkey-wrapper"
    Add-StageBytes $files ([System.Text.Encoding]::UTF8.GetBytes("1`n")) "/etc/tdeenable" "644" "f005" "tde-marker"

    $manifestFiles = @()
    foreach ($file in $files) {
        $chunks = [int][Math]::Ceiling($file.data.Length / [double]$ChunkSize)
        $manifestFiles += [ordered]@{
            id = $file.id
            path = $file.path
            mode = $file.mode
            bytes = $file.bytes
            md5 = $file.md5
            chunks = $chunks
        }
    }

    $commands = @(
        "mkdir -p /data/rootssh/bin /etc/dropbear /home/root/.ssh",
        "ln -sf dropbearmulti /data/rootssh/bin/dropbear",
        "ln -sf dropbearmulti /data/rootssh/bin/dropbearkey",
        "chmod 700 /home/root/.ssh",
        "chmod 600 /home/root/.ssh/authorized_keys",
        "chmod 755 /data/rootssh/bin/dropbearmulti /usr/sbin/dropbear /usr/sbin/dropbearkey",
        "[ -f /etc/dropbear/dropbear_rsa_host_key ] || /usr/sbin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key",
        "killall dropbear 2>/dev/null || true",
        "/usr/sbin/dropbear -R -E -p 22"
    )

    return [pscustomobject]@{
        StageFiles = $files
        Manifest = [ordered]@{
            version = "rootssh-usb-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
            files = $manifestFiles
            commands = $commands
        }
    }
}

function Get-OwnedRuntimeStageSummary {
    if ($ChunkSize -lt 1024 -or $ChunkSize -gt 12000) {
        throw "-ChunkSize should be between 1024 and 12000 to stay under LTCP limits."
    }

    $package = New-OwnedRuntimeManifest
    $totalBytes = 0
    $totalChunks = 0
    $files = @()
    foreach ($file in $package.StageFiles) {
        $chunks = [int][Math]::Ceiling($file.data.Length / [double]$ChunkSize)
        $totalBytes += $file.bytes
        $totalChunks += $chunks
        $files += [ordered]@{
            id = $file.id
            source = $file.source
            path = $file.path
            mode = $file.mode
            bytes = $file.bytes
            base64Bytes = $file.data.Length
            chunks = $chunks
            md5 = $file.md5
        }
    }

    return [ordered]@{
        chunkSize = $ChunkSize
        fileCount = $files.Count
        totalBytes = $totalBytes
        totalChunks = $totalChunks
        files = $files
        installerCommands = $package.Manifest.commands
    }
}

function Invoke-UsbDrain {
    $device = Get-HidDevice
    $inputReportLength = [int]$device.InputReportByteLength
    if ($inputReportLength -le 0) { $inputReportLength = 65 }
    $result = Clear-HidInputQueue -DevicePath ([string]$device.DevicePath) -InputReportLength $inputReportLength
    Write-CompactJson ([ordered]@{
        devicePath = [string]$device.DevicePath
        reports = $result.Reports
        samples = $result.Samples
    })
}

function Invoke-UsbPreflight {
    $device = Get-HidDevice
    $sys = Invoke-HarmonyUsbCommand -CommandName "sys.info" -CommandData "" -ReadTimeoutMs $TimeoutMs
    $writeResult = $null
    if ($WriteProbe) {
        $writeResult = Invoke-LogPut -FileName "codex-usb-preflight.txt" -Body ("ok " + (Get-Date).ToUniversalTime().ToString("o") + "`n")
    }

    Write-CompactJson ([ordered]@{
        device = [ordered]@{
            vendorId = $VendorId
            productId = $ProductId
            devicePath = [string]$device.DevicePath
            inputReportByteLength = [int]$device.InputReportByteLength
            outputReportByteLength = [int]$device.OutputReportByteLength
        }
        transport = [ordered]@{
            timeoutMs = $TimeoutMs
            retryCount = $RetryCount
            retryDelayMs = $RetryDelayMs
            drainReports = $DrainReports
            drainWaitMs = $DrainWaitMs
            looseResponseMatch = [bool]$LooseResponseMatch
        }
        sysinfo = [ordered]@{
            code = Get-HarmonyResponseCode $sys
            complete = $sys.Decode.Complete
            matchedResponse = $sys.MatchedResponse
            appRequestId = $sys.AppRequestId
            attempt = $sys.Attempt
            attempts = $sys.Attempts
            error = $sys.Decode.Error
            payload = $sys.PayloadObject
            readReports = $sys.ReadReports
            candidates = $sys.CandidateDecodes
        }
        writeProbe = if ($writeResult) {
            [ordered]@{
                code = Get-HarmonyResponseCode $writeResult
                complete = $writeResult.Decode.Complete
                matchedResponse = $writeResult.MatchedResponse
                appRequestId = $writeResult.AppRequestId
                attempt = $writeResult.Attempt
                attempts = $writeResult.Attempts
            }
        } else {
            $null
        }
    })
}

function New-UsbAttemptSummary {
    param($Response)
    return [ordered]@{
        code = Get-HarmonyResponseCode $Response
        complete = $Response.Decode.Complete
        matchedResponse = $Response.MatchedResponse
        appRequestId = $Response.AppRequestId
        attempt = $Response.Attempt
        attempts = $Response.Attempts
        error = $Response.Decode.Error
        rawResponseLength = $Response.RawResponseLength
        readReportCount = @($Response.ReadReports).Count
        candidates = $Response.CandidateDecodes
    }
}

function Invoke-UsbResync {
    $results = @()
    for ($i = 1; $i -le $ResyncAttempts; $i++) {
        $sys = Invoke-HarmonyUsbCommand -CommandName "sys.info" -CommandData "" -ReadTimeoutMs $TimeoutMs
        $summary = New-UsbAttemptSummary -Response $sys
        $summary["outerAttempt"] = $i
        $results += $summary
        if ((Get-HarmonyResponseCode $sys) -eq "200" -and $sys.MatchedResponse -and $sys.Decode.Complete) {
            Write-CompactJson ([ordered]@{
                ok = $true
                outerAttempts = $i
                firmware = $sys.PayloadObject.data.fw_ver
                link = $sys.PayloadObject.data.link_type
                results = $results
            })
            return
        }
        if ($i -lt $ResyncAttempts) {
            Start-Sleep -Milliseconds ([Math]::Max(100, $RetryDelayMs))
        }
    }

    Write-CompactJson ([ordered]@{
        ok = $false
        outerAttempts = $ResyncAttempts
        results = $results
    })
}

function Assert-UsbPreflightReady {
    if ($SkipPreflight) {
        Write-Host "usb_preflight_skipped=true"
        return
    }

    Write-Host "Running read-only USB preflight..."
    $sys = Invoke-HarmonyUsbCommand -CommandName "sys.info" -CommandData "" -ReadTimeoutMs $TimeoutMs
    $code = Get-HarmonyResponseCode $sys
    if ($code -ne "200" -or -not $sys.MatchedResponse -or -not $sys.Decode.Complete) {
        $summary = [ordered]@{
            code = $code
            complete = $sys.Decode.Complete
            matchedResponse = $sys.MatchedResponse
            appRequestId = $sys.AppRequestId
            attempt = $sys.Attempt
            attempts = $sys.Attempts
            error = $sys.Decode.Error
            rawResponseLength = $sys.RawResponseLength
            candidates = $sys.CandidateDecodes
        } | ConvertTo-Json -Compress -Depth 8
        throw "USB preflight failed; not starting the requested USB action. Replug USB or restart the hub USB bridge, then retry. Summary: $summary"
    }
    Write-Host ("usb_preflight_ok=true fw={0} attempt={1}/{2}" -f $sys.PayloadObject.data.fw_ver, $sys.Attempt, $sys.Attempts)
}

function Install-RootAccess {
    param([bool]$DoReboot = [bool]$Reboot)

    $pubPath = Resolve-LocalPath $PublicKeyFile
    if (-not (Test-Path $pubPath)) {
        throw "Public key not found: $pubPath"
    }
    $publicKey = (Get-Content -Raw -Path $pubPath).Trim()
    Write-Host "Enabling TDE/root marker over USB..."
    $r = Invoke-LogPut -FileName "../etc/tdeenable" -Body "1`n"
    Assert-HarmonyOk $r "write /etc/tdeenable"

    Write-Host "Creating root SSH key directories..."
    $r = Invoke-JsonPut -Path "../../home/root/.ssh" -File "codex-dir-probe.json" -Content @{created = [int][double]::Parse((Get-Date -UFormat %s))}
    Assert-HarmonyOk $r "create /home/root/.ssh"
    $r = Invoke-JsonPut -Path "../../etc/dropbear" -File "codex-dir-probe.json" -Content @{created = [int][double]::Parse((Get-Date -UFormat %s))}
    Assert-HarmonyOk $r "create /etc/dropbear"

    Write-Host "Installing public key for root/dropbear..."
    $r = Invoke-LogPut -FileName "../home/root/.ssh/authorized_keys" -Body ($publicKey + "`n")
    Assert-HarmonyOk $r "write /home/root/.ssh/authorized_keys"
    $r = Invoke-LogPut -FileName "../etc/dropbear/authorized_keys" -Body ($publicKey + "`n")
    Assert-HarmonyOk $r "write /etc/dropbear/authorized_keys"

    if ($DoReboot) {
        Write-Host "Requesting reboot so the root SSH path comes up cleanly..."
        $r = Invoke-HarmonyUsbCommand -CommandName "setup.firmware?reboot" -CommandData @{} -ReadTimeoutMs 2000
        Write-HarmonyResponse $r
    }
}

function Test-RootSshLogin {
    if ([string]::IsNullOrWhiteSpace($HubIp)) {
        return
    }
    $privPath = Resolve-LocalPath $PrivateKeyFile
    if (-not (Test-Path -LiteralPath $privPath)) {
        Write-Warning "Private key not found for SSH verification: $privPath"
        return
    }
    Protect-PrivateKeyFile -Path $privPath
    $ssh = Get-Command ssh -ErrorAction SilentlyContinue
    if (-not $ssh) {
        Write-Warning "ssh executable not found; skipping login verification."
        return
    }

    Write-Host "Waiting for Dropbear SSH on $HubIp:22..."
    $deadline = [DateTime]::UtcNow.AddSeconds(75)
    $open = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $client = [System.Net.Sockets.TcpClient]::new()
            $async = $client.BeginConnect($HubIp, 22, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(2500)) {
                $client.EndConnect($async)
                $open = $true
                $client.Close()
                break
            }
            $client.Close()
        } catch {
        }
        Start-Sleep -Seconds 2
    }
    Write-Host ("ssh_port_22_open={0}" -f $open)
    if (-not $open) {
        return
    }

    & $ssh.Source -i $privPath `
        -o IdentitiesOnly=yes `
        -o BatchMode=yes `
        -o StrictHostKeyChecking=accept-new `
        -o ConnectTimeout=8 `
        "root@$HubIp" "id; ps | grep '[d]ropbear'"
    Write-Host ("ssh_check_exit_code={0}" -f $LASTEXITCODE)
}

function Test-TcpPortOpen {
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 2500)

    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($async)
            return $true
        }
    } catch {
    } finally {
        if ($client) {
            try {
                $client.Close()
            } catch {
            }
        }
    }
    return $false
}

function Wait-HubLanPort {
    if (-not $WaitForLan) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($HubIp)) {
        Write-Warning "-WaitForLan was set, but -HubIp is empty. Skipping LAN reachability check."
        return
    }

    Write-Host ("Waiting for hub LAN port {0}:{1}..." -f $HubIp, $LanPort)
    $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(1, $LanWaitSeconds))
    $open = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-TcpPortOpen -Address $HubIp -Port $LanPort) {
            $open = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    Write-Host ("lan_port_{0}_open={1}" -f $LanPort, $open)
}

function Get-WifiSsidLabel {
    if ($ShowSsids) {
        return $Ssid
    }
    return "<ssid>"
}

function Invoke-UsbWifiStatus {
    $r = Invoke-HarmonyUsbCommand -CommandName "wifi.status" -CommandData @{donotresolve = 1} -ReadTimeoutMs ([Math]::Max($TimeoutMs, 10000))
    Write-RedactedHarmonyResponse -Response $r -ShowSsids ([bool]$ShowSsids)
    Assert-HarmonyOk $r "wifi.status"
}

function Invoke-UsbWifiScan {
    $r = Invoke-HarmonyUsbCommand -CommandName "wifi.networks" -CommandData @{} -ReadTimeoutMs ([Math]::Max($TimeoutMs, 60000))
    Write-RedactedHarmonyResponse -Response $r -ShowSsids ([bool]$ShowSsids)
    Assert-HarmonyOk $r "wifi.networks"
}

function Invoke-UsbWifiConnect {
    if ([string]::IsNullOrWhiteSpace($Ssid)) {
        throw "-Ssid is required for -Action wifi-connect/provision-wifi."
    }

    $encryptionName = $Encryption
    if ([string]::IsNullOrWhiteSpace($encryptionName)) {
        $encryptionName = "WPA2-PSK"
    }

    if ($encryptionName.ToUpperInvariant() -notin @("NONE", "OPEN") -and [string]::IsNullOrEmpty($WifiPassword)) {
        throw "-WifiPassword is required unless -Encryption is NONE or OPEN."
    }

    $data = [ordered]@{
        ssid = $Ssid
        password = $WifiPassword
        encryption = $encryptionName
    }
    if ($NoSave) {
        $data["nosave"] = $true
    }

    Write-Host ("Provisioning Wi-Fi over USB: ssid={0} encryption={1} save={2}" -f (Get-WifiSsidLabel), $encryptionName, (-not [bool]$NoSave))
    $r = Invoke-HarmonyUsbCommand -CommandName "wifi.connect" -CommandData $data -ReadTimeoutMs ([Math]::Max($TimeoutMs, 40000))
    Write-RedactedHarmonyResponse -Response $r -ShowSsids ([bool]$ShowSsids)
    Assert-HarmonyOk $r "wifi.connect"
    Wait-HubLanPort
}

function Install-UsbRootSsh {
    if ($ChunkSize -lt 1024 -or $ChunkSize -gt 12000) {
        throw "-ChunkSize should be between 1024 and 12000 to stay under LTCP limits."
    }

    Ensure-SshKeyPair
    Assert-UsbPreflightReady
    Install-RootAccess -DoReboot:$false

    Write-Host "Preparing staged USB root SSH package..."
    $package = New-OwnedRuntimeManifest
    $pluginSource = Resolve-LocalPath "rootsshusb.lua"
    $pluginText = Get-Content -Raw -Path $pluginSource
    $pluginManifest = '{"plugin":"rootsshusb"}' + "`n"

    foreach ($dir in @("../../pkg/rootsshusb", "../../data/rootsshusb", "../../data/rootsshusb/chunks")) {
        $r = Invoke-JsonPut -Path $dir -File "codex-dir-probe.json" -Content @{created = [int][double]::Parse((Get-Date -UFormat %s))}
        Assert-HarmonyOk $r "create $dir"
    }

    Write-Host "Installing USB root SSH staging plugin..."
    $r = Invoke-LogPut -FileName "../pkg/rootsshusb/manifest.json" -Body $pluginManifest
    Assert-HarmonyOk $r "write rootsshusb manifest"
    $r = Invoke-LogPut -FileName "../pkg/rootsshusb/rootsshusb.lua" -Body $pluginText
    Assert-HarmonyOk $r "write rootsshusb plugin"

    $totalChunks = 0
    foreach ($file in $package.StageFiles) {
        $totalChunks += [int][Math]::Ceiling($file.data.Length / [double]$ChunkSize)
    }

    $sent = 0
    foreach ($file in $package.StageFiles) {
        $chunks = [int][Math]::Ceiling($file.data.Length / [double]$ChunkSize)
        for ($i = 0; $i -lt $chunks; $i++) {
            $start = $i * $ChunkSize
            $length = [Math]::Min($ChunkSize, $file.data.Length - $start)
            $chunk = $file.data.Substring($start, $length)
            $remote = "../data/rootsshusb/chunks/$($file.id).$($i + 1)"
            $sent++
            Write-Progress -Activity "Uploading Harmony runtime over USB" -Status "$sent / $totalChunks chunks: $($file.path)" -PercentComplete (($sent / [double]$totalChunks) * 100)
            $r = Invoke-LogPut -FileName $remote -Body $chunk
            Assert-HarmonyOk $r "write chunk $remote"
        }
        Write-Host ("staged {0} bytes={1} chunks={2} md5={3}" -f $file.path, $file.bytes, $chunks, $file.md5)
    }
    Write-Progress -Activity "Uploading Harmony runtime over USB" -Completed

    $manifestJson = ($package.Manifest | ConvertTo-Json -Compress -Depth 50) + "`n"
    $r = Invoke-LogPut -FileName "../data/rootsshusb/manifest.json" -Body $manifestJson
    Assert-HarmonyOk $r "write USB installer manifest"

    Write-Host "Triggering hub-side installer..."
    $r = Invoke-HarmonyUsbCommand -CommandName "harmony.automation?discover" -CommandData @{gatewayType = "rootsshusb"} -ReadTimeoutMs 30000
    Write-Host "installer_trigger_code=$(Get-HarmonyResponseCode $r)"
    Start-Sleep -Seconds 2
    $result = Invoke-JsonGet -Path "../../data/rootsshusb" -File "result.json"
    Write-HarmonyResponse $result

    if (-not [string]::IsNullOrWhiteSpace($HubIp)) {
        Test-RootSshLogin
    }
}

switch ($Action) {
    "probe" {
        Invoke-HidProbe
    }
    "drain" {
        Invoke-UsbDrain
    }
    "preflight" {
        Invoke-UsbPreflight
    }
    "resync" {
        Invoke-UsbResync
    }
    "stage-summary" {
        Ensure-SshKeyPair
        Write-CompactJson (Get-OwnedRuntimeStageSummary)
    }
    "sysinfo" {
        $r = Invoke-HarmonyUsbCommand -CommandName "sys.info" -CommandData "" -ReadTimeoutMs $TimeoutMs
        Write-HarmonyResponse $r
    }
    "wifi-status" {
        Invoke-UsbWifiStatus
    }
    "wifi-scan" {
        Invoke-UsbWifiScan
    }
    "wifi-connect" {
        Invoke-UsbWifiConnect
    }
    "provision-wifi" {
        Invoke-UsbWifiConnect
    }
    "root-ssh" {
        Install-UsbRootSsh
    }
}
