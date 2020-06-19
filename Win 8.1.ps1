<#
.SYNOPSIS
	"Windows 8.1 Setup Script" is a set of tweaks for OS fine-tuning and automating the routine tasks
.DESCRIPTION
	Supported Windows 8.1: 6.3.9600 build, x64

	Tested on Home/Pro/Enterprise editions

	Check whether the .ps1 file is encoded in UTF-8 with BOM
	The script can not be executed via PowerShell ISE
	PowerShell must be run with elevated privileges

	Set execution policy to be able to run scripts only in the current PowerShell session:
		Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

	Install before executing
	https://www.microsoft.com/en-us/download/details.aspx?id=42642
	https://docs.microsoft.com/ru-ru/powershell/scripting/windows-powershell/wmf/setup/install-configure

	Running the script is best done on a fresh install
.EXAMPLE
	PS C:\> & '.\Win 8.1.ps1'
.NOTES
	Version: v4.3
	Date: 11.06.2020
	Written by: farag & oZ-Zo
	Thanks to all http://forum.ru-board.com members involved

	Ask a question on
	http://forum.ru-board.com/topic.cgi?forum=62&topic=30617#15
	https://habr.com/en/post/465365/
	https://4pda.ru/forum/index.php?showtopic=523489&st=42860#entry95909388
	https://forums.mydigitallife.net/threads/powershell-script-setup-windows-10.81675/
	https://www.reddit.com/r/PowerShell/comments/go2n5v/powershell_script_setup_windows_10/

	Copyright (c) 2020 farag & oZ-Zo
.LINK
	https://github.com/farag2/Setup-Windows-8.1
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

#region Check
Clear-Host

# Get information about the current culture settings
# Получить сведения о параметрах текущей культуры
if ($PSUICulture -eq "ru-RU")
{
	$RU = $true
}

# Detect the OS bitness
# Определить разрядность ОС
switch ([Environment]::Is64BitOperatingSystem)
{
	$false
	{
		if ($RU)
		{
			Write-Warning -Message "Скрипт поддерживает только Windows 10 x64"
		}
		else
		{
			Write-Warning -Message "The script supports Windows 10 x64 only"
		}
		break
	}
	Default {}
}

# Detect the PowerShell bitness
# Определить разрядность PowerShell
switch ([IntPtr]::Size -eq 8)
{
	$false
	{
		if ($RU)
		{
			Write-Warning -Message "Скрипт поддерживает только PowerShell x64"
		}
		else
		{
			Write-Warning -Message "The script supports PowerShell x64 only"
		}
		break
	}
	Default {}
}

# Detect whether the script is running via PowerShell ISE
# Определить, запущен ли скрипт в PowerShell ISE
if ($psISE)
{
	if ($RU)
	{
		Write-Warning -Message "Скрипт не может быть запущен в PowerShell ISE"
	}
	else
	{
		Write-Warning -Message "The script can not be run via PowerShell ISE"
	}
	break
}
#endregion Check

#region Begin
Set-StrictMode -Version Latest

# Сlear $Error variable
# Очистка переменной $Error
$Error.Clear()

# Set the encoding to UTF-8 without BOM for the PowerShell session
# Установить кодировку UTF-8 без BOM для текущей сессии PowerShell
if ($RU)
{
	ping.exe | Out-Null
	$OutputEncoding = [System.Console]::OutputEncoding = [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
}

# Create a restore point
# Создать точку восстановления
if ($RU)
{
	$Title = "Точка восстановления"
	$Message = "Чтобы создайте точку восстановления, введите необходимую букву"
	$Options = "&Создать", "&Не создавать", "&Пропустить"
}
else
{
	$Title = "Restore point"
	$Message = "To create a restore point enter the required letter"
	$Options = "&Create", "&Do not create", "&Skip"
}
$DefaultChoice = 2
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		if (-not (Get-ComputerRestorePoint))
		{
			Enable-ComputerRestore -Drive $env:SystemDrive
		}
		# Set system restore point creation frequency to 5 minutes
		# Установить частоту создания точек восстановления на 5 минут
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 5 -Force
		# Descriptive name format for the restore point: <Month>.<date>.<year> <time>
		# Формат описания точки восстановления: <дата>.<месяц>.<год> <время>
		$CheckpointDescription = Get-Date -Format "dd.MM.yyyy HH:mm"
		Checkpoint-Computer -Description $CheckpointDescription -RestorePointType MODIFY_SETTINGS
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force
	}
	"1"
	{
		if ($RU)
		{
			$Title = "Точки восстановления"
			$Message = "Чтобы удалить все точки восстановления, введите необходимую букву"
			$Options = "&Удалить", "&Пропустить"
		}
		else
		{
			$Title = "Restore point"
			$Message = "To remove all restore points enter the required letter"
			$Options = "&Delete", "&Skip"
		}
		$DefaultChoice = 1
		$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

		switch ($Result)
		{
			"0"
			{
				# Delete all restore points
				# Удалить все точки восстановения
				Get-CimInstance -ClassName Win32_ShadowCopy | Remove-CimInstance
			}
			"1"
			{
				if ($RU)
				{
					Write-Verbose -Message "Пропущено" -Verbose
				}
				else
				{
					Write-Verbose -Message "Skipped" -Verbose
				}
			}
		}
	}
	"2"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}
#endregion Begin

#region Privacy & Telemetry
# Turn off "Diagnostics Tracking Service"
# Отключить службу "Diagnostics Tracking Service"
Get-Service -ServiceName DiagTrack | Stop-Service
Get-Service -ServiceName DiagTrack | Set-Service -StartupType Disabled

# Turn off Windows Error Reporting
# Отключить отчеты об ошибках Windows
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -PropertyType DWord -Value 1 -Force

# Change Windows Feedback frequency to "Never"
# Изменить частоту формирования отзывов на "Никогда"
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Siuf\Rules))
{
	New-Item -Path HKCU:\Software\Microsoft\Siuf\Rules -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -PropertyType DWord -Value 0 -Force

# Turn off diagnostics tracking scheduled tasks
# Отключить задачи диагностического отслеживания
$tasks = @(
	# Aggregates and uploads Application Telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
	# Сбор и передача данных дистанционного отслеживания приложений
	"AitAgent"
	# The Bluetooth CEIP (Customer Experience Improvement Program) task collects Bluetooth related statistics and information about your machine and sends it to Microsoft
	# Задача программы улучшения качества Bluetooth собирает статистику по Bluetooth, а также сведения о вашем компьютере, и отправляет их в корпорацию Майкрософт
	"BthSQM"
	# If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft
	# Если пользователь изъявил желание участвовать в программе по улучшению качества программного обеспечения Windows, эта задача будет собирать и отправлять сведения о работе программного обеспечения в Майкрософт
	"Consolidator"
	# Initializes Family Safety monitoring and enforcement
	# Инициализация контроля и применения правил семейной безопасности
	"FamilySafetyMonitor"
	# Synchronizes the latest settings with the Microsoft family features service
	# Синхронизирует последние параметры со службой функций семьи учетных записей Майкрософт
	"FamilySafetyRefresh"
	# Protects user files from accidental loss by copying them to a backup location when the system is unattended
	# Защищает файлы пользователя от случайной потери за счет их копирования в резервное расположение, когда система находится в автоматическом режиме
	"File History (maintenance mode)"
	# The Kernel CEIP (Customer Experience Improvement Program) task collects additional information about the system and sends this data to Microsoft
	# Осуществляется сбор дополнительных данных о системе, которые затем передаются в корпорацию Майкрософт
	"KernelCeipTask"
	# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program.
	# Собирает телеметрические данные программы при участии в Программе улучшения качества программного обеспечения Майкрософт
	"Microsoft Compatibility Appraiser"
	# The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program
	# Для пользователей, участвующих в программе контроля качества программного обеспечения, служба диагностики дисков Windows предоставляет общие сведения о дисках и системе в корпорацию Майкрософт
	"Microsoft-Windows-DiskDiagnosticDataCollector"
	"NetworkStateChangeTask"
	# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
	# Сбор телеметрических данных программы при участии в программе улучшения качества ПО
	"ProgramDataUpdater"
	# This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program
	# Эта задача собирает и загружает данные SQM при участии в программе улучшения качества программного обеспечения
	"Proxy"
	# Windows Error Reporting task to process queued reports
	# Задача отчетов об ошибках обрабатывает очередь отчетов
	"QueueReporting"
	# Task that collects data for SmartScreen in Windows
	# Задача, выполняющая сбор данных для SmartScreen в Windows
	"SmartScreenSpecific"
	# The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine
	# При выполнении задачи программы улучшения качества ПО шины USB (USB CEIP) осуществляется сбор статистических данных об использовании универсальной последовательной шины USB и сведений о компьютере
	"UsbCeip"
	# Measures a system's performance and capabilities
	# Измеряет быстродействие и возможности системы
	"WinSAT"
)
Get-ScheduledTask -TaskName $tasks | Disable-ScheduledTask

# This idle task reorganizes the cache files used to display the start menu
# Эта задача периода бездействия реорганизует файлы кэша, используемые для отображения меню "Пуск"
Unregister-ScheduledTask -TaskName "Optimize Start Menu*" -Confirm:$false
#endregion Privacy & Telemetry

#region UI & Personalization
# Show "This PC" on Desktop
# Отобразить "Этот компьютер" на рабочем столе
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0 -Force

# Do not use check boxes to select items
# Не использовать флажки для выбора элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 0 -Force

# Show hidden files, folders, and drives
# Показывать скрытые файлы, папки и диски
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 1 -Force

# Show more details in file transfer dialog
# Развернуть диалог переноса файлов
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force

# Show file name extensions
# Показывать расширения для зарегистрированных типов файлов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force

# Do not hide folder merge conflicts
# Не скрывать конфликт слияния папок
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -PropertyType DWord -Value 0 -Force

# Open File Explorer to: "This PC"
# Открывать проводник для: "Этот компьютер"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force

# Do not show all folders in the navigation pane
# Не отображать все папки в области навигации
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name NavPaneShowAllFolders -PropertyType DWord -Value 0 -Force

# Show the Ribbon expanded in File Explorer
# Отображать ленту проводника в развернутом виде
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Name MinimizedStateTabletModeOff -PropertyType DWord -Value 0 -Force

<#
Display recycle bin files delete confirmation
Function [WinAPI.UpdateExplorer]::PostMessage() call required at the end

Запрашивать подтверждение на удаление файлов в корзину
В конце необходим вызов функции [WinAPI.UpdateExplorer]::PostMessage()
#>
$ShellState = Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState
$ShellState[4] = 51
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShellState -PropertyType Binary -Value $ShellState -Force

# Always show all icons in the notification area
# Всегда отображать все значки в области уведомлений
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -PropertyType DWord -Value 0 -Force

# Unpin Microsoft Internet Explorer from taskbar
# Открепить Microsoft Internet Explorer от панели задач
$Signature = @{
	Namespace = "WinAPI"
	Name = "GetStr"
	Language = "CSharp"
	MemberDefinition = @"
		// https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/8#issue-227159084
		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr GetModuleHandle(string lpModuleName);
		[DllImport("user32.dll", CharSet = CharSet.Auto)]
		internal static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int nBufferMax);
		public static string GetString(uint strId)
		{
			IntPtr intPtr = GetModuleHandle("shell32.dll");
			StringBuilder sb = new StringBuilder(255);
			LoadString(intPtr, strId, sb, sb.Capacity);
			return sb.ToString();
		}
"@
}
if (-not ("WinAPI.GetStr" -as [type]))
{
	Add-Type @Signature -Using System.Text
}
# Extract the "Unpin from taskbar" string from shell32.dll
# Извлечь строку "Открепить от панели задач" из shell32.dll
$unpin = [WinAPI.GetStr]::GetString(5387)
$apps = (New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
$apps | Where-Object -FilterScript {$_.Path -eq "Microsoft.InternetExplorer.Default"} | ForEach-Object -Process {$_.Verbs() | Where-Object -FilterScript {$_.Name -eq $unpin} | ForEach-Object -Process {$_.DoIt()}}

# Unpin the Microsoft Store shortcut from taskbar
# Открепить ярлык Магазина от панели задач
if (-not (Test-Path -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoPinningStoreToTaskbar -PropertyType DWord -Value 1 -Force

# Set the large icons in the Control Panel
# Установить крупные значки в Панели управления
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 1 -Force

# Do not show "New App Installed" notification
# Не показывать уведомление "Установлено новое приложение"
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -PropertyType DWord -Value 1 -Force

# Turn off JPEG desktop wallpaper import quality reduction
# Отключить снижение качества при импорте фонового изображение рабочего стола в формате JPEG
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force

# Expand Task manager window
# Раскрыть окно Диспетчера задач
$taskmgr = Get-Process -Name Taskmgr -ErrorAction Ignore
if ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
Start-Process -FilePath Taskmgr
Start-Sleep -Seconds 1
$taskmgr = Get-Process -Name Taskmgr -ErrorAction Ignore
if ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
do
{
	Start-Sleep -Milliseconds 100
	$preferences = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -ErrorAction Ignore
}
until ($preferences)
$preferences.Preferences[28] = 0
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -PropertyType Binary -Value $preferences.Preferences -Force

# Do not add the "- Shortcut" for created shortcuts
# Нe дoбaвлять "- яpлык" для coздaвaeмыx яpлыкoв
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name link -PropertyType Binary -Value ([byte[]](00,00,00,00)) -Force

# Do not display lockscreen
# Не отображать экран блокировки
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -PropertyType DWord -Value 1 -Force
#endregion UI & Personalization

#region System
# Turn off hibernate if device is not a laptop
# Отключить режим гибернации, если устройство не является ноутбуком
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2)
{
	POWERCFG /HIBERNATE OFF
}

# Change %TEMP% environment variable path to the %SystemDrive%\Temp
# Изменить путь переменной среды для %TEMP% на %SystemDrive%\Temp
if (-not (Test-Path -Path $env:SystemDrive\Temp))
{
	New-Item -Path $env:SystemDrive\Temp -ItemType Directory -Force
}
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "User")
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Machine")
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Process")
New-ItemProperty -Path HKCU:\Environment -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force

[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "User")
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Machine")
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Process")
New-ItemProperty -Path HKCU:\Environment -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force

# Spooler restart
# Перезапуск Диспетчер печати
Restart-Service -Name Spooler -Force
Remove-Item -Path $env:SystemRoot\Temp -Recurse -Force -ErrorAction Ignore
Remove-Item -Path $env:LOCALAPPDATA\Temp -Recurse -Force -ErrorAction Ignore

# Turn on Win32 long paths
# Включить длинные пути Win32
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force

# Display the Stop error information on the BSoD
# Отображать Stop-ошибку при появлении BSoD
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 1 -Force

# Do not preserve zone information in file attachments
# Не хранить сведения о зоне происхождения вложенных файлов
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force

# Turn off Admin Approval Mode for administrators
# Отключить использование режима одобрения администратором для встроенной учетной записи администратора
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 0 -Force

# Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
# Включить доступ к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -PropertyType DWord -Value 1 -Force

# Always wait for the network at computer startup and logon
# Всегда ждать сеть при запуске и входе в систему
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -PropertyType DWord -Value 1 -Force

# Turn off Windows features
# Отключить компоненты Windows
$WindowsOptionalFeatures = @(
	# Windows Fax and Scan
	# Факсы и сканирование
	"FaxServicesClientPackage"
	# Legacy Components
	# Компоненты прежних версий
	"LegacyComponents"
	# Media Features
	# Компоненты работы с мультимедиа
	"MediaPlayback"
	# PowerShell 2.0
	"MicrosoftWindowsPowerShellV2"
	"MicrosoftWindowsPowershellV2Root"
	# Microsoft XPS Document Writer
	# Средство записи XPS-документов (Microsoft)
	"Printing-XPSServices-Features"
	# Work Folders Client
	# Клиент рабочих папок
	"WorkFolders-Client"
	# XPS Viewer
	# Просмотрщик XPS
	"Xps-Foundation-Xps-Viewer"
)
Disable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatures -NoRestart

Write-Verbose 111 -Verbose
# Turn on updates for other Microsoft products
# Включить автоматическое обновление для других продуктов Microsoft
(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")

# Set power management scheme
# Установить схему управления питания
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 2)
{
	# Balanced for laptop
	# Сбалансированная для ноутбука
	POWERCFG /SETACTIVE SCHEME_BALANCED
}
else
{
	# High performance for desktop
	# Высокая производительность для стационарного ПК
	POWERCFG /SETACTIVE SCHEME_MIN
}

# Use latest installed .NET runtime for all apps
# Использовать последнюю установленную версию .NET для всех приложенийNew-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force

# Do not allow the computer (if device is not a laptop) to turn off the network adapters to save power
# Запретить отключение сетевых адаптеров для экономии энергии (если устройство не является ноутбуком)
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2)
{
	$adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement | Where-Object -FilterScript {$_.AllowComputerToTurnOffDevice -ne "Unsupported"}
	foreach ($adapter in $adapters)
	{
		$adapter.AllowComputerToTurnOffDevice = "Disabled"
		$adapter | Set-NetAdapterPowerManagement
	}
}

# Set the default input method to the English language
# Установить метод ввода по умолчанию на английский язык
Set-WinDefaultInputMethodOverride "0409:00000409"
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name BlockUserInputMethodsForSignIn -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 1 -PropertyType String -Value 00000409 -Force
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 2 -PropertyType String -Value 00000419 -Force

# Do not show user first sign-in animation
# Не показывать анимацию при первом входе в систему
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -PropertyType DWord -Value 0 -Force

# Change location of the user folders
# Изменить расположение пользовательских папок
function UserShellFolder
{
<#
.SYNOPSIS
	Change location of the each user folders using SHSetKnownFolderPath function
.EXAMPLE
	UserShellFolder -UserFolder Desktop -FolderPath "C:\Desktop"
.NOTES
	User files or folders won't me moved to the new location
#>
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
		[string]
		$UserFolder,

		[Parameter(Mandatory = $true)]
		[string]
		$FolderPath
	)

	function KnownFolderPath
	{
	<#
	.SYNOPSIS
		Redirect user folders to a new location
	.EXAMPLE
		KnownFolderPath -KnownFolder Desktop -Path "C:\Desktop"
	.NOTES
		User files or folders won't me moved to the new location
	#>
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true)]
			[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
			[string]
			$KnownFolder,

			[Parameter(Mandatory = $true)]
			[string]
			$Path
		)

		$KnownFolders = @{
			"Desktop"	= @("B4BFCC3A-DB2C-424C-B029-7FE99A87C641");
			"Documents"	= @("FDD39AD0-238F-46AF-ADB4-6C85480369C7", "f42ee2d3-909f-4907-8871-4c22fc0bf756");
			"Downloads"	= @("374DE290-123F-4565-9164-39C4925E467B", "7d83ee9b-2244-4e70-b1f5-5393042af1e4");
			"Music"		= @("4BD8D571-6D19-48D3-BE97-422220080E43", "a0c69a99-21c8-4671-8703-7934162fcf1d");
			"Pictures"	= @("33E28130-4E1E-4676-835A-98395C3BC3BB", "0ddd015d-b06c-45d5-8c4c-f59713854639");
			"Videos"	= @("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "35286a68-3c57-41a1-bbb1-0eae73d76c95");
		}

		$Signature = @{
			Namespace = "WinAPI"
			Name = "KnownFolders"
			Language = "CSharp"
			MemberDefinition = @"
				[DllImport("shell32.dll")]
				public extern static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);
"@
		}
		if (-not ("WinAPI.KnownFolders" -as [type]))
		{
			Add-Type @Signature
		}

		foreach ($guid in $KnownFolders[$KnownFolder])
		{
			[WinAPI.KnownFolders]::SHSetKnownFolderPath([ref]$guid, 0, 0, $Path)
		}
		(Get-Item -Path $Path -Force).Attributes = "ReadOnly"
	}

	$UserShellFoldersRegName = @{
		"Desktop"	=	"Desktop"
		"Documents"	=	"Personal"
		"Downloads"	=	"{374DE290-123F-4565-9164-39C4925E467B}"
		"Music"		=	"My Music"
		"Pictures"	=	"My Pictures"
		"Videos"	=	"My Video"
	}

	$UserShellFoldersGUID = @{
		"Desktop"	=	"{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}"
		"Documents"	=	"{F42EE2D3-909F-4907-8871-4C22FC0BF756}"
		"Downloads"	=	"{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}"
		"Music"		=	"{A0C69A99-21C8-4671-8703-7934162FCF1D}"
		"Pictures"	=	"{0DDD015D-B06C-45D5-8C4C-F59713854639}"
		"Videos"	=	"{35286A68-3C57-41A1-BBB1-0EAE73D76C95}"
	}

	# Hidden desktop.ini for each type of user folders
	# Скрытый desktop.ini для каждого типа пользовательских папок
	$DesktopINI = @{
		"Desktop"	=	"",
						"[.ShellClassInfo]",
						"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21769",
						"IconResource=%SystemRoot%\system32\imageres.dll,-183"
		"Documents"	=	"",
						"[.ShellClassInfo]",
						"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770",
						"IconResource=%SystemRoot%\system32\imageres.dll,-112",
						"IconFile=%SystemRoot%\system32\shell32.dll",
						"IconIndex=-235"
		"Downloads"	=	"",
						"[.ShellClassInfo]","LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21798",
						"IconResource=%SystemRoot%\system32\imageres.dll,-184"
		"Music"		=	"",
						"[.ShellClassInfo]","LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21790",
						"InfoTip=@%SystemRoot%\system32\shell32.dll,-12689",
						"IconResource=%SystemRoot%\system32\imageres.dll,-108",
						"IconFile=%SystemRoot%\system32\shell32.dll","IconIndex=-237"
		"Pictures"	=	"",
						"[.ShellClassInfo]",
						"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21779",
						"InfoTip=@%SystemRoot%\system32\shell32.dll,-12688",
						"IconResource=%SystemRoot%\system32\imageres.dll,-113",
						"IconFile=%SystemRoot%\system32\shell32.dll",
						"IconIndex=-236"
		"Videos"	=	"",
						"[.ShellClassInfo]",
						"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21791",
						"InfoTip=@%SystemRoot%\system32\shell32.dll,-12690",
						"IconResource=%SystemRoot%\system32\imageres.dll,-189",
						"IconFile=%SystemRoot%\system32\shell32.dll","IconIndex=-238"
	}

	# Determining the current user folder path
	# Определяем текущее значение пути пользовательской папки
	$UserShellFolderRegValue = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersRegName[$UserFolder]
	if ($UserShellFolderRegValue -ne $FolderPath)
	{
		if ((Get-ChildItem -Path $UserShellFolderRegValue | Measure-Object).Count -ne 0)
		{
			if ($RU)
			{
				Write-Error -Message "В папке $UserShellFolderRegValue осталась файлы. Переместите их вручную в новое расположение" -ErrorAction SilentlyContinue
			}
			else
			{
				Write-Error -Message "Some files left in the $UserShellFolderRegValue folder. Move them manually to a new location" -ErrorAction SilentlyContinue
			}
		}

		# Creating a new folder if there is no one
		# Создаем новую папку, если таковая отсутствует
		if (-not (Test-Path -Path $FolderPath))
		{
			New-Item -Path $FolderPath -ItemType Directory -Force
		}

		KnownFolderPath -KnownFolder $UserFolder -Path $FolderPath
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersGUID[$UserFolder] -PropertyType ExpandString -Value $FolderPath -Force

		Set-Content -Path "$FolderPath\desktop.ini" -Value $DesktopINI[$UserFolder] -Encoding Unicode -Force
		(Get-Item -Path "$FolderPath\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
		(Get-Item -Path "$FolderPath\desktop.ini" -Force).Refresh()
	}
}

<#
.SYNOPSIS
	The "Show menu" function using PowerShell with the up/down arrow keys and enter key to make a selection
.EXAMPLE
	ShowMenu -Menu $ListOfItems -Default $DefaultChoice
.NOTES
	Doesn't work in PowerShell ISE
#>
function ShowMenu
{
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[string]
		$Title,

		[Parameter(Mandatory = $true)]
		[array]
		$Menu,

		[Parameter(Mandatory = $true)]
		[int]
		$Default
	)

	Write-Information -MessageData $Title -InformationAction Continue

	$minY = [Console]::CursorTop
	$y = [Math]::Max([Math]::Min($Default, $Menu.Count), 0)
	do
	{
		[Console]::CursorTop = $minY
		[Console]::CursorLeft = 0
		$i = 0
		foreach ($item in $Menu)
		{
			if ($i -ne $y)
			{
				Write-Information -MessageData ('  {0}. {1}  ' -f ($i+1), $item) -InformationAction Continue
			}
			else
			{
				Write-Information -MessageData ('[ {0}. {1} ]' -f ($i+1), $item) -InformationAction Continue
			}
			$i++
		}

		$k = [Console]::ReadKey()
		switch ($k.Key)
		{
			"UpArrow"
			{
				if ($y -gt 0)
				{
					$y--
				}
			}
			"DownArrow"
			{
				if ($y -lt ($Menu.Count - 1))
				{
					$y++
				}
			}
			"Enter"
			{
				return $Menu[$y]
			}
		}
	}
	while ($k.Key -notin ([ConsoleKey]::Escape, [ConsoleKey]::Enter))
}

# Store all drives letters to use them within ShowMenu function
# Сохранить все буквы диска, чтобы использовать их в функции ShowMenu
if ($RU)
{
	Write-Verbose "Получение дисков..." -Verbose
}
else
{
	Write-Verbose "Retrieving drives..." -Verbose
}
$DriveLetters = @((Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Get-Partition | Get-Volume | Where-Object -FilterScript {($null -ne $_.DriveLetter) -and ("" -ne $_.DriveLetter)}).DriveLetter | Sort-Object)

if ($DriveLetters.Count -gt 1)
{
	# If the number of disks is more than one, set the second drive in the list as default drive
	# Если количество дисков больше одного, сделать второй диск в списке диском по умолчанию
	$Default = 1
}
else
{
	$Default = 0
}

# Desktop
# Рабочий стол
$Title = ""
if ($RU)
{
	$Message = "Чтобы изменить местоположение папки `"Рабочий стол`", введите необходимую букву"
	Write-Warning "`nФайлы не будут перенесены"
	$Options = "&Изменить", "&Пропустить"
}
else
{
	$Message = "To change the location of the Desktop folder enter the required letter"
	Write-Warning "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		if ($RU)
		{
			$Title = "`nВыберите диск, в корне которого будет создана папка для `"Рабочий стол`""
		}
		else
		{
			$Title = "`nSelect the drive within the root of which the `"Desktop`" folder will be created"
		}
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Desktop -FolderPath "${SelectedDrive}:\Desktop"
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}

# Documents
# Документы
$Title = ""
if ($RU)
{
	$Message = "Чтобы изменить местоположение папки `"Документы`", введите необходимую букву"
	Write-Warning "`nФайлы не будут перенесены"
	$Options = "&Изменить", "&Пропустить"
}
else
{
	$Message = "To change the location of the Documents folder enter the required letter"
	Write-Warning "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		if ($RU)
		{
			$Title = "`nВыберите диск, в корне которого будет создана папка для `"Документы`""
		}
		else
		{
			$Title = "`nSelect the drive within the root of which the `"Documents`" folder will be created"
		}
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Documents -FolderPath "${SelectedDrive}:\Documents"
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}

# Downloads
# Загрузки
$Title = ""
if ($RU)
{
	$Message = "Чтобы изменить местоположение папки `"Загрузки`", введите необходимую букву"
	Write-Warning "`nФайлы не будут перенесены"
	$Options = "&Изменить", "&Пропустить"
}
else
{
	$Message = "To change the location of the Downloads folder enter the required letter"
	Write-Warning "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		if ($RU)
		{
			$Title = "`nВыберите диск, в корне которого будет создана папка для `"Загрузки`""
		}
		else
		{
			$Title = "`nSelect the drive within the root of which the `"Downloads`" folder will be created"
		}
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Downloads -FolderPath "${SelectedDrive}:\Downloads"
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}

# Music
# Музыка
$Title = ""
if ($RU)
{
	$Message = "Чтобы изменить местоположение папки `"Музыка`", введите необходимую букву"
	Write-Warning "`nФайлы не будут перенесены"
	$Options = "&Изменить", "&Пропустить"
}
else
{
	$Message = "To change the location of the Music folder enter the required letter"
	Write-Warning "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		if ($RU)
		{
			$Title = "`nВыберите диск, в корне которого будет создана папка для `"Музыка`""
		}
		else
		{
			$Title = "`nSelect the drive within the root of which the `"Music`" folder will be created"
		}
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Music -FolderPath "${SelectedDrive}:\Music"
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}


# Pictures
# Изображения
$Title = ""
if ($RU)
{
	$Message = "Чтобы изменить местоположение папки `"Изображения`", введите необходимую букву"
	Write-Warning "`nФайлы не будут перенесены"
	$Options = "&Изменить", "&Пропустить"
}
else
{
	$Message = "To change the location of the Pictures folder enter the required letter"
	Write-Warning "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		if ($RU)
		{
			$Title = "`nВыберите диск, в корне которого будет создана папка для `"Изображения`""
		}
		else
		{
			$Title = "`nSelect the drive within the root of which the `"Pictures`" folder will be created"
		}
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Pictures -FolderPath "${SelectedDrive}:\Pictures"
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}

# Videos
# Видео
$Title = ""
if ($RU)
{
	$Message = "Чтобы изменить местоположение папки `"Видео`", введите необходимую букву"
	Write-Warning "`nФайлы не будут перенесены"
	$Options = "&Изменить", "&Пропустить"
}
else
{
	$Message = "To change the location of the Videos folder enter the required letter"
	Write-Warning "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		if ($RU)
		{
			$Title = "`nВыберите диск, в корне которого будет создана папка для `"Видео`""
		}
		else
		{
			$Title = "`nSelect the drive within the root of which the `"Videos`" folder will be created"
		}
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Videos -FolderPath "${SelectedDrive}:\Videos"
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}

# Turn off Help page opening by F1 key
# Отключить открытие справки по нажатию F1
if (-not (Test-Path -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
{
	New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -PropertyType String -Value "" -Force

# Turn on Num Lock at startup
# Включить Num Lock при загрузке
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483650 -Force

# Turn off sticky Shift key after pressing 5 times
# Отключить залипание клавиши Shift после 5 нажатий
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force

# Turn off AutoPlay for all media and devices
# Отключить автозапуск для всех носителей и устройств
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 1 -Force

# Turn off thumbnail cache removal
# Отключить удаление кэша миниатюр
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force

# Turn on network discovery and file and printers sharing if device is not domain-joined
# Включить сетевое обнаружение и общий доступ к файлам и принтерам, если устройство не присоединенно к домену
if ((Get-NetConnectionProfile).NetworkCategory -ne "DomainAuthenticated")
{
	Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752", "@FirewallAPI.dll,-28502" | Set-NetFirewallRule -Profile Private -Enabled True
	Set-NetConnectionProfile -NetworkCategory Private
}

# Remove printers
# Удалить принтеры
Remove-Printer -Name Fax, "Microsoft XPS Document Writer" -ErrorAction Ignore
#endregion System

#region Windows Photo Viewer
# Add "Windows Photo Viewer" to Open with context menu
# Добавить Средство просмотра фотографий Windows в пункт контекстного меню "Открыть с помощью"New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open -Name MuiVerb -PropertyType String -Value "@photoviewer.dll,-3043" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\command -Name "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\DropTarget -Name Clsid -PropertyType String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\print\command -Name "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\DropTarget -Name Clsid -PropertyType String -Value "{60fd46de-f830-4894-a628-6fa81bc0190d}" -Force

# Associate BMP, JPEG, PNG, TIF to "Windows Photo Viewer"
# Ассоциация BMP, JPEG, PNG, TIF со Средством просмотра фотографий Windows
cmd.exe --% /c ftype Paint.Picture=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1
cmd.exe --% /c ftype jpegfile=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1
cmd.exe --% /c ftype pngfile=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1
cmd.exe --% /c ftype TIFImage.Document=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1
cmd.exe --% /c assoc .bmp=Paint.Picture
cmd.exe --% /c assoc .jpg=jpegfile
cmd.exe --% /c assoc .jpeg=jpegfile
cmd.exe --% /c assoc .png=pngfile
cmd.exe --% /c assoc .tif=TIFImage.Document
cmd.exe --% /c assoc .tiff=TIFImage.Document
cmd.exe --% /c assoc Paint.Picture\DefaultIcon=%SystemRoot%\System32\imageres.dll,-70
cmd.exe --% /c assoc jpegfile\DefaultIcon=%SystemRoot%\System32\imageres.dll,-72
cmd.exe --% /c assoc pngfile\DefaultIcon=%SystemRoot%\System32\imageres.dll,-71
cmd.exe --% /c assoc TIFImage.Document\DefaultIcon=%SystemRoot%\System32\imageres.dll,-122
#endregion Windows Photo Viewer

#region UWP apps
# Uninstall all UWP apps from all accounts
# Удалить все UWP-приложения из всех учетных записей
Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Remove-AppxPackage -Verbose
#endregion UWP apps

#region Scheduled tasks
<#
Create a Windows cleaning up task in the Task Scheduler
The task runs every 90 days
Создать задачу в Планировщике задач по очистке Windows
Задача выполняется каждые 90 дней
#>
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
	Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore
}

$VolumeCaches = @(
	# Device driver packages
	# Пакеты драйверов устройств
	"Device Driver Packages",
	# Previous Windows Installation(s)
	# Предыдущие установки Windows
	"Previous Installations",
	# Файлы журнала установки
	"Setup Log Files",
	# Temporary Setup Files
	"Temporary Setup Files",
	# Microsoft Defender Antivirus
	"Windows Defender",
	# Windows upgrade log files
	# Файлы журнала обновления Windows
	"Windows Upgrade Log Files"
)
foreach ($VolumeCache in $VolumeCaches)
{
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache" -Name StateFlags1337 -PropertyType DWord -Value 2 -Force
}

$PS1Script = '
# Process startup info
# Параметры запуска процесса
$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = "$env:SystemRoot\system32\cleanmgr.exe"
$ProcessInfo.Arguments = "/sagerun:1337"
$ProcessInfo.UseShellExecute = $true
$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

# Process object using the startup info
# Объект процесса, используя заданные параметры
$Process = New-Object System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo

# Start the process
# Запуск процесса
$Process.Start() | Out-Null

Start-Sleep -Seconds 3
$SourceMainWindowHandle = (Get-Process -Name cleanmgr).MainWindowHandle

function MinimizeWindow
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		$Process
	)

	$ShowWindowAsync = @{
	Namespace = "WinAPI"
	Name = "Win32ShowWindowAsync"
	Language = "CSharp"
	MemberDefinition = @"
		[DllImport("user32.dll")]
		public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@
	}
	if (-not ("WinAPI.Win32ShowWindowAsync" -as [type]))
	{
		Add-Type @ShowWindowAsync
	}

	$MainWindowHandle = (Get-Process -Name $Process).MainWindowHandle
	[WinAPI.Win32ShowWindowAsync]::ShowWindowAsync($MainWindowHandle, 2)
}

while ($true)
{
	$CurrentMainWindowHandle = (Get-Process -Name cleanmgr).MainWindowHandle
	if ([int]$SourceMainWindowHandle -ne [int]$CurrentMainWindowHandle)
	{
		MinimizeWindow -Process cleanmgr
		break
	}
	Start-Sleep -Milliseconds 5
}

$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
# Cleaning up unused updates
# Очистка неиспользованных обновлений
$ProcessInfo.FileName = "$env:SystemRoot\system32\dism.exe"
$ProcessInfo.Arguments = "/Online /English /Cleanup-Image /StartComponentCleanup /NoRestart"
$ProcessInfo.UseShellExecute = $true
$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

# Process object using the startup info
# Объект процесса, используя заданные параметры
$Process = New-Object System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo

# Start the process
# Запуск процесса
$Process.Start() | Out-Null
'
$EncodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PS1Script))

$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -EncodedCommand $EncodedScript"
$Trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 90 -At 9am
$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
if ($RU)
{
	$Description =
	"Очистка неиспользуемых файлов и обновлений Windows, используя встроенную программу Очистка диска. Чтобы расшифровать закодированную строку используйте [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`"строка`"))"
}
else
{
	$Description =
	"Cleaning up unused Windows files and updates using built-in Disk cleanup app. To decode encoded command use [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`"string`"))"
}
$Parameters = @{
	"TaskName"		= "Windows Cleanup"
	"TaskPath"		= "Setup Script"
	"Action"		= $Action
	"Description"	= $Description
	"Settings"		= $Settings
	"Trigger"		= $Trigger
}
Register-ScheduledTask @Parameters -User $env:USERNAME -RunLevel Highest -Force

<#
Create a task in the Task Scheduler to clear the %SystemRoot%\SoftwareDistribution\Download folder
The task runs on Thursdays every 4 weeks
Создать задачу в Планировщике задач по очистке папки %SystemRoot%\SoftwareDistribution\Download
Задача выполняется по четвергам каждую 4 неделю
#>
$Argument = "
	(Get-Service -Name wuauserv).WaitForStatus('Stopped', '01:00:00')
	Get-ChildItem -Path $env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
"
$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument $Argument
$Trigger = New-JobTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Thursday -At 9am
$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
if ($RU)
{
	$Description = "Очистка папки %SystemRoot%\SoftwareDistribution\Download"
}
else
{
	$Description = "The %SystemRoot%\SoftwareDistribution\Download folder cleaning"
}
$Parameters = @{
	"TaskName"		= "SoftwareDistribution"
	"TaskPath"		= "Setup Script"
	"Action"		= $Action
	"Description"	= $Description
	"Settings"		= $Settings
	"Trigger"		= $Trigger
}
Register-ScheduledTask @Parameters -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force

<#
Create a task in the Task Scheduler to clear the %TEMP% folder
The task runs every 62 days
Создать задачу в Планировщике задач по очистке папки %TEMP%
Задача выполняется каждые 62 дня
#>
$Argument = "Get-ChildItem -Path $env:TEMP -Force -Recurse | Remove-Item -Force -Recurse"
$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument $Argument
$Trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 62 -At 9am
$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
if ($RU)
{
	$Description = "Очистка папки %TEMP%"
}
else
{
	$Description = "The %TEMP% folder cleaning"
}
$Parameters = @{
	"TaskName"		= "Temp"
	"TaskPath"		= "Setup Script"
	"Action"		= $Action
	"Description"	= $Description
	"Settings"		= $Settings
	"Trigger"		= $Trigger
}
Register-ScheduledTask @Parameters -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force
#endregion Scheduled tasks

#region Windows Defender & Security
# Fixing broken Add-MpPreference cmdlet
# Исправляем сломанный комадлет Add-MpPreference
# https://yamanxworld.blogspot.com/2017/05/windows-81-windows-defender.html
$Defenderpsd1 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1"
cmd.exe --% /c "takeown /F %WINDIR%\system32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1"
cmd.exe --% /c "icacls %WINDIR%\system32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1 /grant:r %USERNAME%:F"
(Get-Content -Path $Defenderpsd1) | ForEach-Object -Process {
	$_.replace("'MSFT_MpSignature.cdxml',", "'MSFT_MpSignature.cdxml')").
	replace("'Remove-MpThreat',", "'Remove-MpThreat')")
} | Set-Content -Path $Defenderpsd1
(Get-Content -Path $Defenderpsd1 | Select-String -Pattern "MSFT_MpWDOScan.cdxml" -NotMatch) | Set-Content -Path $Defenderpsd1 -Force
(Get-Content -Path $Defenderpsd1 | Select-String -Pattern "Start-MpScan" -NotMatch) | Set-Content -Path $Defenderpsd1 -Force
(Get-Content -Path $Defenderpsd1 | Select-String -Pattern "Start-MpWDOScan" -NotMatch) | Set-Content -Path $Defenderpsd1 -Force

# Add exclusion folder from Windows Defender Antivirus scanning
# Добавить в исключение Windows Defender папку
if ($RU)
{
	$Title = "Microsoft Defender"
	$Message = "Чтобы исключить папку из списка сканирования антивредоносной программы Microsoft Defender, введите необходимую букву"
	$Options = "&Исключить папку", "&Пропустить"
}
else
{
	$Title = "Microsoft Defender"
	$Message = "To exclude folder from Microsoft Defender Antivirus Scan enter the required letter"
	$Options = "&Exclude folder", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		Add-Type -AssemblyName System.Windows.Forms
		$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
		if ($RU)
		{
			$FolderBrowserDialog.Description = "Выберите папку"
		}
		else
		{
			$FolderBrowserDialog.Description = "Select a folder"
		}
		$FolderBrowserDialog.RootFolder = "MyComputer"
		# Focus on open file dialog
		# Перевести фокус на диалог открытия файла
		$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
		$FolderBrowserDialog.ShowDialog($tmp)
		if ($FolderBrowserDialog.SelectedPath)
		{
			Add-MpPreference -ExclusionPath $FolderBrowserDialog.SelectedPath -Force
		}
		$Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}

# Add exclusion file from Microsoft Defender Antivirus scanning
# Добавить файл в список исключений сканирования Microsoft Defender
if ($RU)
{
	$Title = "Microsoft Defender"
	$Message = "Чтобы исключить файл из списка сканирования антивредоносной программы Microsoft Defender, введите необходимую букву"
	$Options = "&Исключить файл", "&Пропустить"
}
else
{
	$Title = "Microsoft Defender"
	$Message = "To exclude file from Microsoft Defender Antivirus Scan enter the required letter"
	$Options = "&Exclude file", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		Add-Type -AssemblyName System.Windows.Forms
		$OpenFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
		if ($RU)
		{
			$OpenFileDialog.Filter = "Все файлы (*.*)|*.*"
		}
		else
		{
			$OpenFileDialog.Filter = "All Files (*.*)|*.*"
		}
		$OpenFileDialog.InitialDirectory = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
		$OpenFileDialog.Multiselect = $false
		# Focus on open file dialog
		# Перевести фокус на диалог открытия файла
		$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
		$OpenFileDialog.ShowDialog($tmp)
		if ($OpenFileDialog.FileName)
		{
			Add-MpPreference -ExclusionPath $OpenFileDialog.FileName -Force
		}
		$Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}

# Turn on events auditing generated when a process is created or starts
# Включить аудит событий, возникающих при создании или запуске процесса
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

# Include command line in process creation events
# Включать командную строку в событиях создания процесса
if ($RU)
{
	$OutputEncoding = [System.Console]::OutputEncoding = [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
}
$ProcessCreation = auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /r | ConvertFrom-Csv | Select-Object -ExpandProperty "Inclusion Setting"
if ($ProcessCreation -ne "No Auditing")
{
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force
}

# Turn on logging for all Windows PowerShell modules
# Включить ведение журнала для всех модулей Windows PowerShell
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -PropertyType String -Value * -Force

# Turn on logging of all PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log
# Включить регистрацию всех вводимых сценариев PowerShell в журнале событий Microsoft-Windows-PowerShell/Operational
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force

# Turn off SmartScreen for apps and files
# Отключить SmartScreen для приложений и файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force

# Turn off Windows Script Host
# Отключить Windows Script Host
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -PropertyType DWord -Value 0 -Force
#endregion Windows Defender & Security

#region Context menu
# Add the "Extract" item to Windows Installer (.msi) context menu
# Добавить пункт "Извлечь" в контекстное меню Windows Installer (.msi)
if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force
}
$Value = "{0}" -f 'msiexec.exe /a "%1" /qb TARGETDIR="%1 extracted"'
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(Default)" -PropertyType String -Value $Value -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-31382" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force

# Add the "Install" item to the .cab archives context menu
# Добавить пункт "Установить" в контекстное меню .cab архивов
if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Force
}
$Value = "{0}" -f 'cmd /c DISM.exe /Online /Add-Package /PackagePath:"%1" /NoRestart & pause'
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Name "(Default)" -PropertyType String -Value $Value -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs -Name MUIVerb -PropertyType String -Value "@shell32.dll,-10210" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs -Name HasLUAShield -PropertyType String -Value "" -Force

# Add the "Run as different user" item to the .exe files types context menu
# Добавить "Запуск от имени другого пользователя" в контекстное меню .exe файлов
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force -ErrorAction Ignore

# Hide the "Print" item from the .bat and .cmd context menu
# Скрыть пункт "Печать" из контекстного меню .bat и .cmd файлов
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force

# Hide the "Include in Library" item from the context menu
# Скрыть пункт "Добавить в библиотеку" из контекстного меню
New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(Default)" -PropertyType String -Value "-{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force

# Hide the "Send to" item from the folders context menu
# Скрыть пункт "Отправить" из контекстного меню папок
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(Default)" -PropertyType String -Value "-{7BA4C740-9E81-11CF-99D3-00AA004AE837}" -Force

# Hide the "Turn on BitLocker" item from the context menu
# Скрыть пункт "Включить BitLocker" из контекстного меню
if (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -eq "Professional" -or $_.Edition -eq "Enterprise"})
{
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\manage-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\unlock-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}

# Remove the "Bitmap image" item from the "New" context menu
# Удалить пункт "Точечный рисунок" из контекстного меню "Создать"
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Force -ErrorAction Ignore

# Remove the "Contact" item from the "New" context menu
# Удалить пункт "Контакт" из контекстного меню "Создать"
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.contact\ShellNew -Force -ErrorAction Ignore

# Remove the "Rich Text Document" item from the "New" context menu
# Удалить пункт "Документ в формате RTF" из контекстного меню "Создать"
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Force -ErrorAction Ignore

# Remove the "Compressed (zipped) Folder" item from the "New" context menu
# Удалить пункт "Сжатая ZIP-папка" из контекстного меню "Создать"
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Force -ErrorAction Ignore

# Make the "Open", "Print", "Edit" context menu items available, when more than 15 items selected
# Сделать доступными элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -PropertyType DWord -Value 300 -Force

# Hide the "Look for an app in the Microsoft Store" item in "Open with" dialog
# Скрыть пункт "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью"
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force

# Hide the "Previous Versions" tab from files and folders context menu and the "Restore previous versions" context menu item
# Скрыть вкладку "Предыдущие версии" в свойствах файлов и папок и пункт контекстного меню "Восстановить прежнюю версию"
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -PropertyType DWord -Value 1 -Force

# Remove the "Pin to Start" item from the .exe files context menu
# Удалить пункт "Закрепить на начальном экране" из контекстного меню .exe файлов
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen -Force -ErrorAction Ignore

# Remove the "Pin to Start" item from the folders context menu
# Удалить пункт "Закрепить на начальном экране" из контекстного меню папок
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen -Force -ErrorAction Ignore
#endregion Context menu

#region Refresh
$UpdateExplorer = @{
	Namespace = "WinAPI"
	Name = "UpdateExplorer"
	Language = "CSharp"
	MemberDefinition = @"
		private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
		private const int WM_SETTINGCHANGE = 0x1a;
		private const int SMTO_ABORTIFHUNG = 0x0002;

		[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		static extern bool SendNotifyMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);
		[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		private static extern IntPtr SendMessageTimeout(IntPtr hWnd, int Msg, IntPtr wParam, string lParam, int fuFlags, int uTimeout, IntPtr lpdwResult);
		[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
		public static void Refresh()
		{
			// Update desktop icons
			// Обновить иконки рабочего стола
			SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
			// Update environment variables
			// Обновить переменные среды
			SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, null, SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
			// Update taskbar
			// Обновить панель задач
			SendNotifyMessage(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings");
		}

		private static readonly IntPtr hWnd = new IntPtr(65535);
		private const int Msg = 273;
		// Virtual key ID of the F5 in File Explorer
		// Виртуальный код клавиши F5 в проводнике
		private static readonly UIntPtr UIntPtr = new UIntPtr(41504);

		[DllImport("user32.dll", SetLastError=true)]
		public static extern int PostMessageW(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam);
		public static void PostMessage()
		{
			// F5 pressing simulation to refresh the desktop
			// Симуляция нажатия F5 для обновления рабочего стола
			PostMessageW(hWnd, Msg, UIntPtr, IntPtr.Zero);
		}
"@
}
if (-not ("WinAPI.UpdateExplorer" -as [type]))
{
	Add-Type @UpdateExplorer
}

# Send F5 pressing simulation to refresh the desktop
# Симулировать нажатие F5 для обновления рабочего стола
[WinAPI.UpdateExplorer]::PostMessage()
# Refresh desktop icons, environment variables, taskbar
# Обновить иконки рабочего стола, переменные среды, панель задач
[WinAPI.UpdateExplorer]::Refresh()
#endregion Refresh

# Errors output
# Вывод ошибок
if ($Error)
{
	($Error | ForEach-Object -Process {
		if ($RU)
		{
			[PSCustomObject] @{
				Строка = $_.InvocationInfo.ScriptLineNumber
				"Ошибки/предупреждения" = $_.Exception.Message
			}
		}
		else
		{
			[PSCustomObject] @{
				Line = $_.InvocationInfo.ScriptLineNumber
				"Errors/Warnings" = $_.Exception.Message
			}
		}
	} | Sort-Object -Property Line | Format-Table -AutoSize -Wrap | Out-String).Trim()
}