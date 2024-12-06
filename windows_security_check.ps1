# Windows安全检查与应急响应工具
param (
    [switch]$OnlySuspicious  # 是否只保存可疑信息
)

# 初始化变量
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$date = Get-Date -Format "yyyyMMdd-HHmmss"
$baseDir = Join-Path $scriptPath "Security_Check_$date"
$resultFile = Join-Path $baseDir "check_result.txt"
$dangerFile = Join-Path $baseDir "danger_file.txt"

# 定义可疑特征
$SuspiciousPatterns = @{
    ProcessNames = @(
        "mimikatz", "psexec", "netcat", "nmap", "wireshark",
        "powersploit", "metasploit", "cobalt", "empire", "ncat"
    )
    Ports = @(
        4444, 5555, 6666, 7777, 8888, 9999,  # 常见后门端口
        1080, 3128, 8080, 12345, 54321       # 代理和其他可疑端口
    )
    Services = @(
        "vnc", "remote", "rdp", "telnet", "ssh", "ftp",
        "proxy", "tunnel", "tor", "hidden"
    )
    Files = @(
        "*.bat", "*.ps1", "*.vbs", "*.exe", "*.dll",
        "*backdoor*", "*trojan*", "*hack*", "*crack*"
    )
}

# 初始化输出
function Initialize-Output {
    if (!(Test-Path $baseDir)) {
        New-Item -ItemType Directory -Force -Path $baseDir | Out-Null
    }
    Set-Content -Path $resultFile -Value "Windows安全检查结果`n" -Encoding UTF8
    Set-Content -Path $dangerFile -Value "发现的危险项：`n" -Encoding UTF8
}

# 修改输出函数，使其保存更详细的信息
function Write-CheckResult {
    param (
        [string]$Message,
        [switch]$IsDanger,
        [object]$Data,        # 添加数据对象参数
        [string]$DataFormat = "Table"  # 数据格式化方式
    )
    
    # 格式化时间戳
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $formattedMessage = "[$timestamp] $Message`n"
    
    # 如果提供了数据对象，根据指定格式输出
    if ($Data) {
        $formattedData = switch ($DataFormat) {
            "Table" { $Data | Format-Table -AutoSize * | Out-String -Width 4096 }
            "List"  { $Data | Format-List * | Out-String }
            default { $Data | Format-Table -AutoSize * | Out-String -Width 4096 }
        }
        $formattedMessage += $formattedData
    }
    
    if ($IsDanger) {
        Add-Content -Path $dangerFile -Value $formattedMessage -Encoding UTF8
    }
    if (!$OnlySuspicious -or $IsDanger) {
        Add-Content -Path $resultFile -Value $formattedMessage -Encoding UTF8
    }
}

# 1. 系统信息检查
function Get-SystemInfo {
    Write-CheckResult "============ 系统信息 ============"
    
    # 基本系统信息
    $sysInfo = Get-ComputerInfo | Select-Object CsName, CsDomain, CsUserName, OsName, OsVersion, 
        OsBuildNumber, OsArchitecture, OsLanguage, OsInstallDate, OsLastBootUpTime,
        CsProcessors, CsNumberOfLogicalProcessors, CsPhyicallyInstalledMemory
    Write-CheckResult "系统基本信息:" -Data $sysInfo -DataFormat "List"
    
    # IP配置
    $networkInfo = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
    Write-CheckResult "网络配置信息:" -Data $networkInfo
    
    # 补丁信息
    $hotfixes = Get-HotFix | Sort-Object -Property InstalledOn -Descending | 
        Select-Object HotFixID, Description, InstalledBy, InstalledOn
    Write-CheckResult "已安装的补丁:" -Data $hotfixes
    
    # 系统环境变量
    $envVars = Get-ChildItem Env: | Select-Object Name, Value
    Write-CheckResult "系统环境变量:" -Data $envVars
}

# 2. 用户账户检查
function Get-UserInfo {
    Write-CheckResult "============ 用户账户信息 ============"
    
    # 检查本地用户
    $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, 
        PasswordLastSet, PasswordExpires, UserMayChangePassword, Description
    Write-CheckResult "本地用户列表:" -Data $users
    
    # 检查本地组
    $groups = Get-LocalGroup | Select-Object Name, Description, SID
    Write-CheckResult "本地用户组:" -Data $groups
    
    # 检查管理员组成员
    $admins = Get-LocalGroupMember -Group "Administrators" | 
        Select-Object Name, PrincipalSource, ObjectClass
    Write-CheckResult "管理员组成员:" -Data $admins
    
    # 检查空密码账户
    $emptyPassUsers = $users | Where-Object PasswordRequired -eq $false
    if ($emptyPassUsers) {
        Write-CheckResult "[警告] 发现空密码账户:" -Data $emptyPassUsers -IsDanger
    }
    
    # 检查最近创建的用户
    $recentUsers = $users | Where-Object {
        $_.Created -gt (Get-Date).AddDays(-30)
    }
    if ($recentUsers) {
        Write-CheckResult "[注意] 最近30天内创建的用户:" -Data $recentUsers -IsDanger
    }
}

# 3. 网络连接检查
function Get-NetworkInfo {
    Write-CheckResult "============ 网络连接信息 ============"
    
    # 检查网络适配器
    $adapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, 
        MacAddress, LinkSpeed, MediaType, PhysicalMediaType
    Write-CheckResult "网络适配器信息:" -Data $adapters
    
    # 检查IP配置
    $ipConfig = Get-NetIPAddress | Select-Object InterfaceAlias, AddressFamily, 
        IPAddress, PrefixLength, Type
    Write-CheckResult "IP配置信息:" -Data $ipConfig
    
    # 检查活动连接
    $connections = Get-NetTCPConnection | Where-Object State -eq "Established" |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, 
            State, OwningProcess, @{
                Name='ProcessName';
                Expression={(Get-Process -Id $_.OwningProcess).ProcessName}
            }
    Write-CheckResult "活动的网络连接:" -Data $connections
    
    # 检查可疑端口
    $suspiciousConns = $connections | Where-Object {
        $_.LocalPort -in $SuspiciousPatterns.Ports -or
        $_.RemotePort -in $SuspiciousPatterns.Ports
    }
    if ($suspiciousConns) {
        Write-CheckResult "[警告] 发现可疑端口连接:" -Data $suspiciousConns -IsDanger
    }
}

# 4. 进程检查
function Get-ProcessInfo {
    Write-CheckResult "`n============ 进程信息 ============"
    
    # 获取所有进程
    $processes = Get-Process | Select-Object Name, Id, Path, Company, Description
    Write-CheckResult "运行中的进程:`n$($processes | Format-Table | Out-String)"
    
    # 检查可疑进程
    $suspiciousProcs = $processes | Where-Object {
        $proc = $_
        $SuspiciousPatterns.ProcessNames | Where-Object { $proc.Name -like "*$_*" }
    }
    if ($suspiciousProcs) {
        Write-CheckResult "[警告] 发现可疑进程:`n$($suspiciousProcs | Format-Table | Out-String)" -IsDanger
    }
}

# 5. 服务检查
function Get-ServiceInfo {
    Write-CheckResult "`n============ 服务信息 ============"
    
    # 获取所有服务
    $services = Get-Service | Where-Object Status -eq "Running"
    Write-CheckResult "运行中的服务:`n$($services | Format-Table | Out-String)"
    
    # 检查可疑服务
    $suspiciousServices = $services | Where-Object {
        $service = $_
        $SuspiciousPatterns.Services | Where-Object { $service.Name -like "*$_*" }
    }
    if ($suspiciousServices) {
        Write-CheckResult "[警告] 发现可疑服务:`n$($suspiciousServices | Format-Table | Out-String)" -IsDanger
    }
}

# 6. 启动项检查
function Get-StartupInfo {
    Write-CheckResult "`n============ 启动项信息 ============"
    
    # 获取启动项
    $startupItems = Get-CimInstance Win32_StartupCommand
    Write-CheckResult "系统启动项:`n$($startupItems | Format-Table | Out-String)"
    
    # 检查可疑启动项
    $suspiciousStartup = $startupItems | Where-Object {
        $item = $_
        $SuspiciousPatterns.Files | Where-Object { $item.Command -like $_ }
    }
    if ($suspiciousStartup) {
        Write-CheckResult "[警告] 发现可疑启动项:`n$($suspiciousStartup | Format-Table | Out-String)" -IsDanger
    }
}

# 7. 计划任务检查
function Get-ScheduledTaskInfo {
    Write-CheckResult "`n============ 计划任务信息 ============"
    
    # 获取计划任务
    $tasks = Get-ScheduledTask | Where-Object State -eq "Ready"
    Write-CheckResult "启用的计划任务:`n$($tasks | Format-Table | Out-String)"
    
    # 检查可疑任务
    $suspiciousTasks = $tasks | Where-Object {
        $task = $_
        $SuspiciousPatterns.Files | Where-Object { $task.Actions.Execute -like $_ }
    }
    if ($suspiciousTasks) {
        Write-CheckResult "[警告] 发现可疑计划任务:`n$($suspiciousTasks | Format-Table | Out-String)" -IsDanger
    }
}

# 8. 防火墙检查
function Get-FirewallInfo {
    Write-CheckResult "`n============ 防火墙信息 ============"
    
    # 检查防火墙状态
    $fwProfiles = Get-NetFirewallProfile
    Write-CheckResult "防火墙配置:`n$($fwProfiles | Format-Table | Out-String)"
    
    # 检查可疑规则
    $suspiciousRules = Get-NetFirewallRule | Where-Object {
        $_.Enabled -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow"
    }
    if ($suspiciousRules) {
        Write-CheckResult "[警告] 发现可疑防火墙规则:`n$($suspiciousRules | Format-Table | Out-String)" -IsDanger
    }
}

# 主函数
function Main {
    Write-Host "开始进行Windows系统安全检查..." -ForegroundColor Green
    Initialize-Output
    
    # 执行各项检查
    Get-SystemInfo
    Get-UserInfo
    Get-NetworkInfo
    Get-ProcessInfo
    Get-ServiceInfo
    Get-StartupInfo
    Get-ScheduledTaskInfo
    Get-FirewallInfo
    
    Write-Host "`n检查完成！结果已保存到：" -ForegroundColor Green
    Write-Host "- 检查结果：$resultFile" -ForegroundColor Cyan
    Write-Host "- 可疑项目：$dangerFile" -ForegroundColor Yellow
}

# 执行主函数
Main 