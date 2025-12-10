
$banner = @"
###############################################################
#                                                             #
#           Windows Incident Response Readiness              #
#                                                             #
###############################################################

                                    ###########                            
                                ####################                       
                             ########################                      
                          ##########################                       
                         ##########################                        
                       ###########################%                        
                      #######################  *##                         
                     #####################                                 
                     ###################                                   
                    ########################                              
                    ############# #############                            
                    #############################                          
                    ##############################                         
                    ###############################                        
                    #######   #####################                        
                     #####    ################  ####                       
                     #####    ################### ###                      
                      ####     #######################                     
                      ####     ###################%####                    
                      ####     ###################                         
                      ####     ###################                         
                     ####      #######   #########                         
                    ###        *           #######%                        
                    #                         #####                        
                                                 ##                   

"@

Write-Host $banner -ForegroundColor Green

# Display system info and purpose
$os = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "Analyzing $os System for Incident Response Readiness..." -ForegroundColor Cyan
Write-Output ""

# Clear output file
$outputPath = "output.txt"
"CheckID,Result,Value" | Out-File -FilePath $outputPath -Encoding UTF8

# Called to write result of check to output.txt with CheckID, Result (Pass/Fail/Error), and Raw Value
function Write-CheckResult {
    param (
        [string]$Check,
        [string]$Result,
        [string]$Value
    )

    Write-Host "`n[*] $Check" -ForegroundColor Yellow

    switch ($Result.ToUpper()) {
        "PASS"   { Write-Host "[+] Result: $Result" -ForegroundColor Green }
        "FAIL"   { Write-Host "[+] Result: $Result" -ForegroundColor Red }
        default  { Write-Host "[+] Result: $Result" -ForegroundColor Magenta }
    }

    Write-Host "[i] Value: $Value" -ForegroundColor Cyan

    # Append to output.txt in CSV format: CheckID,Result,Value
    Add-Content -Path "output.txt" -Value "$Check,$Result,$Value"
}

# TaskScheduler: Track the creation, deletion, modification, and execution of scheduled tasks.
function Check-TaskSchedulerLogging {
    $chkID = "TaskScheduler"
    Write-Output ""
    Write-Host "Checking Task Scheduler Logging..."

    $taskSchedPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational"

    try {
        if (Test-Path $taskSchedPath) {
            $enabled = (Get-ItemProperty -Path $taskSchedPath -Name "Enabled" -ErrorAction Stop).Enabled
            if ($enabled -eq 1) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value $enabled
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value $enabled
            }
        } else {
            Write-CheckResult -Check $chkID -Result "Error" -Value "Registry Path Not Found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "Error" -Value "$($_.Exception.Message)"
    }
}



# PowerShell Module Logging
function Check-PowerShellModuleLogging {
    $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $key = "EnableModuleLogging"
    $chkID = "PSModuleLogging"

    try {
        if (Test-Path $path) {
            $value = (Get-ItemProperty -Path $path -Name $key -ErrorAction Stop).$key
            if ($value -eq 1) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value $value
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value $value
            }
        } else {
            Write-CheckResult -Check $chkID -Result "Error" -Value "Registry Path Not Found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "Error" -Value "$($_.Exception.Message)"
    }
}


# PowerShell Script Block Logging
function Check-PowerShellScriptBlockLogging {
    $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $key = "EnableScriptBlockLogging"
    $chkID = "PSScriptBlockLogging"

    try {
        if (Test-Path $path) {
            $value = (Get-ItemProperty -Path $path -Name $key -ErrorAction Stop).$key
            if ($value -eq 1) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value $value
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value $value
            }
        } else {
            Write-CheckResult -Check $chkID -Result "Error" -Value "Registry Path Not Found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "Error" -Value "$($_.Exception.Message)"
    }
}


# PowerShell Transcription Logging
function Check-PowerShellTranscriptionLogging {
    $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
    $key = "EnableTranscripting"
    $chkID = "PSTranscriptionLogging"

    try {
        if (Test-Path $path) {
            $value = (Get-ItemProperty -Path $path -Name $key -ErrorAction Stop).$key
            if ($value -eq 1) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value $value
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value $value
            }
        } else {
            Write-CheckResult -Check $chkID -Result "Error" -Value "Registry Path Not Found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "Error" -Value "$($_.Exception.Message)"
    }
}



# Audit Policy for Process Creation
function Check-AuditProcessCreation {
    $chkID = "AuditProcessCreation"

    try {
        $auditOutput = auditpol /get /subcategory:"Process Creation" 2>&1

        if ($LASTEXITCODE -eq 0) {
            # Try to extract just the subcategory and its setting
            $line = $auditOutput | Where-Object { $_ -match "Process Creation" }
            if ($line) {
                $parts = ($line -split '\s{2,}' | Where-Object { $_ -ne "" })
                $setting = $parts[-1]

                if ($setting -match "Success") {
                    Write-CheckResult -Check $chkID -Result "PASS" -Value "$setting"
                } else {
                    Write-CheckResult -Check $chkID -Result "FAIL" -Value "$setting"
                }
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "Subcategory not found"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "Error" -Value "Error querying audit policy: $auditOutput"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "Error" -Value "$($_.Exception.Message)"
    }
}



# Command Line Auditing: Include command line in process creation events
function Check-CommandLineAuditing {
    $chkID = "CommandLineAuditing"
    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $keyName = "ProcessCreationIncludeCmdLine_Enabled"

    try {
        if (Test-Path $regPath) {
            $value = (Get-ItemProperty -Path $regPath -Name $keyName -ErrorAction Stop).$keyName
            if ($value -eq 1) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value $value
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value $value
            }
        } else {
            Write-CheckResult -Check $chkID -Result "Error" -Value "Registry Path Not Found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "Error" -Value "$($_.Exception.Message)"
    }
}



# Audit Policy: Filtering Platform Connection
function Check-AuditFilteringPlatformConnection {
    $chkID = "AuditFilteringPlatformConnection"
    Write-Output ""
    Write-Host "Checking 'Filtering Platform Connection' Auditing..."

    try {
        $auditPolicy = auditpol /get /subcategory:"Filtering Platform Connection" 2>&1

        if ($LASTEXITCODE -eq 0) {
            $setting = ($auditPolicy | Where-Object { $_ -match "Filtering Platform Connection" }) -replace '.*\s{2,}', ''
            
            if ($setting -match "Success") {
                Write-CheckResult -Check $chkID -Result "PASS" -Value "$setting"
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "$setting"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "Error" -Value "Error querying audit policy: $auditPolicy"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "Error" -Value "$($_.Exception.Message)"
    }
}



# Prefetch: Helps retain execution history (evidence of execution and usage patterns)
function Check-EnablePrefetch {
    $chkID = "EnablePrefetch"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    $keyName = "EnablePrefetcher"

    Write-Host "`nChecking Prefetch..."

    try {
        if (Test-Path $regPath) {
            $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
            if ($props.PSObject.Properties.Name -contains $keyName) {
                $value = $props.$keyName
                if ($value -ge 1) {
                    Write-CheckResult -Check $chkID -Result "PASS" -Value "$value"
                } else {
                    Write-CheckResult -Check $chkID -Result "FAIL" -Value "$value"
                }
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry value '$keyName' not set"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry path '$regPath' not found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading registry: $($_.Exception.Message)"
    }
}



# WMI Logging: CIMOM (logs WMI provider infrastructure activity)
function Check-WMICIMOMLogging {
    $chkID = "WMICIMOMLogging"
    $regPath = "HKLM:\SOFTWARE\Microsoft\WBEM\CIMOM"
    $keyName = "Logging"

    Write-Host "`nChecking WMI CIMOM Logging..."

    try {
        if (Test-Path $regPath) {
            $value = (Get-ItemProperty -Path $regPath -Name $keyName -ErrorAction Stop).$keyName
            if ($value -eq 2) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value "$value"
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "$value"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry path '$regPath' not found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading registry: $($_.Exception.Message)"
    }
}



# WMI Logging: ViewProvider (tracks WMI queries via ViewProvider logs)
function Check-WMIViewProviderLogging {
    $chkID = "WMIViewProviderLogging"
    $regPath = "HKLM:\SOFTWARE\Microsoft\WBEM\PROVIDERS\Logging\ViewProvider"
    $keyName = "Level"

    Write-Host "`nChecking WMI ViewProvider Logging..."

    try {
        if (Test-Path $regPath) {
            $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
            if ($props.PSObject.Properties.Name -contains $keyName) {
                $value = $props.$keyName
                if ($value -eq 2) {
                    Write-CheckResult -Check $chkID -Result "PASS" -Value "$value"
                } else {
                    Write-CheckResult -Check $chkID -Result "FAIL" -Value "$value"
                }
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry value '$keyName' not set"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry path '$regPath' not found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading registry: $($_.Exception.Message)"
    }
}



# PrintService Logging: Tracks print job activity (can reveal lateral movement or document exfiltration)
function Check-PrintServiceLogging {
    $chkID = "PrintServiceLogging"
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Operational"
    $keyName = "Enabled"

    Write-Host "`nChecking PrintService Logging..."

    try {
        if (Test-Path $regPath) {
            $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
            if ($props.PSObject.Properties.Name -contains $keyName) {
                $value = $props.$keyName
                if ($value -eq 1) {
                    Write-CheckResult -Check $chkID -Result "PASS" -Value "$value"
                } else {
                    Write-CheckResult -Check $chkID -Result "FAIL" -Value "$value"
                }
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry value '$keyName' not set"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry path '$regPath' not found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading registry: $($_.Exception.Message)"
    }
}

#Call all Logging Checks
Check-TaskSchedulerLogging

Write-Output ""
Write-Output "Checking PowerShell Logging..."
Check-PowerShellModuleLogging
Check-PowerShellScriptBlockLogging
Check-PowerShellTranscriptionLogging

Write-Output ""
Write-Host "Checking Process Execution Event Logging..."

Check-AuditProcessCreation
Check-CommandLineAuditing
Check-AuditFilteringPlatformConnection
Check-EnablePrefetch
Check-WMICIMOMLogging
Check-WMIViewProviderLogging
Check-PrintServiceLogging 

# System Log Size 
function Check-SystemLogSize {
    $chkID = "SystemLogSize"

    try {
        $systemLog = Get-WinEvent -ListLog System -ErrorAction Stop
        $logSizeMB = [math]::Round($systemLog.MaximumSizeInBytes / 1MB, 2)

        if ($systemLog.MaximumSizeInBytes -ge 2147483648) {
            Write-CheckResult -Check $chkID -Result "PASS" -Value "$logSizeMB MB"
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "$logSizeMB MB"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading System log size: $($_.Exception.Message)"
    }
}



# Security Log Size
function Check-SecurityLogSize {
    $chkID = "SecurityLogSize"

    try {
        $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
        $logSizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)

        if ($securityLog.MaximumSizeInBytes -ge 2147483648) {
            Write-CheckResult -Check $chkID -Result "PASS" -Value "$logSizeMB MB"
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "$logSizeMB MB"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading Security log size: $($_.Exception.Message)"
    }
}

# PowerShell Log Size
function Check-PowerShellLogSize {
    $chkID = "PowerShellLogSize"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell"
    $keyName = "MaxSize"

    try {
        if (Test-Path $regPath) {
            [int]$value = (Get-ItemProperty -Path $regPath -Name $keyName -ErrorAction Stop).$keyName
            if ($value -ge 2000000) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value "$value KB"
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "$value KB"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry path not found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading registry: $($_.Exception.Message)"
    }
}


# WMI-Activity Log Size – CIMOM
function Check-WMICIMOMLogSize {
    $chkID = "WMICIMOMLogSize"
    $regPath = "HKLM:\SOFTWARE\Microsoft\WBEM\CIMOM"
    $keyName = "Log File Max Size"

    try {
        if (Test-Path $regPath) {
            $value = [int](Get-ItemProperty -Path $regPath -Name $keyName -ErrorAction Stop)."Log File Max Size"
            if ($value -ge 2000000) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value "$value KB"
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "$value KB"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry path not found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading registry: $($_.Exception.Message)"
    }
}



# WMI-Activity Log Size – ViewProvider
function Check-WMIViewProviderLogSize {
    $chkID = "WMIViewProviderLogSize"

    $regPath = "HKLM:\SOFTWARE\Microsoft\WBEM\PROVIDERS\Logging\ViewProvider"
    $keyName = "MaxFileSize"

    try {
        if (Test-Path $regPath) {
            $value = [int](Get-ItemProperty -Path $regPath -Name $keyName -ErrorAction Stop).$keyName
            if ($value -ge 2000000) {
                Write-CheckResult -Check $chkID -Result "PASS" -Value "$value KB"
            } else {
                Write-CheckResult -Check $chkID -Result "FAIL" -Value "$value KB"
            }
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "Registry path not found"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading registry: $($_.Exception.Message)"
    }
}


# Task Scheduler Log Size
function Check-TaskSchedulerLogSize {
    $chkID = "TaskSchedulerLogSize"

    try {
        $taskLog = Get-WinEvent -ListLog "Microsoft-Windows-TaskScheduler/Operational" -ErrorAction Stop
        $logSizeMB = [math]::Round($taskLog.MaximumSizeInBytes / 1MB, 2)

        if ($taskLog.MaximumSizeInBytes -ge 2147483648) {
            Write-CheckResult -Check $chkID -Result "PASS" -Value "$logSizeMB MB"
        } else {
            Write-CheckResult -Check $chkID -Result "FAIL" -Value "$logSizeMB MB"
        }
    } catch {
        Write-CheckResult -Check $chkID -Result "FAIL" -Value "Error reading Task Scheduler log size: $($_.Exception.Message)"
    }
}


# Call all log size checks
Write-Host "`nANALYZING LOG SIZES..."

Check-SystemLogSize
Check-SecurityLogSize
Check-PowerShellLogSize
Check-WMICIMOMLogSize
Check-WMIViewProviderLogSize
Check-TaskSchedulerLogSize


Write-Output ""
Write-Output "DONE SCANNING"