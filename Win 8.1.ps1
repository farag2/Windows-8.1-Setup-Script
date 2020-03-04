<#
.SYNOPSIS
	The PowerShell script is a set of tweaks for fine-tuning Windows 8.1 and automating the routine tasks.
.DESCRIPTION
	Supported Windows versions: Windows 8.1 with Update x64

	Check whether file is encoded in UTF-8 with BOM.
	PowerShell must be run with elevated privileges;
	Set PowerShell execution policy: Set-ExecutionPolicy -ExecutionPolicy Bypass -Force to be able to run .ps1 files.

	Read the code you run carefully.
	Some functions are presented as an example only.
	You must be aware of the meaning of the functions in the code.
	If you're not sure what the script does, do not run it.
	Strongly recommended to run the script after fresh installation.
.EXAMPLE
	PS C:\WINDOWS\system32> & '.\Win 8.1.ps1'
.NOTES
	v4.1 — 03.03.2020
	Written by: farag
	Thanks to all ru-board.com members involved
	Ask a question on
	- http://forum.ru-board.com/topic.cgi?forum=62&topic=30617#15
.LINK
	https://github.com/farag2/Windows-10-Setup-Script
#>

#Requires -RunAsAdministrator
#Requires -Version 4

#region Preparation
Clear-Host

# Get information about the current culture settings
# Получить сведения о параметрах текущей культуры
if ($PSUICulture -eq "ru-RU")
{
	$RU = $true
}
# Detect the OS bitness
# Определить разрядность ОС
if (-not ([Environment]::Is64BitOperatingSystem))
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
# Detect the PowerShell bitness
# Определить разрядность PowerShell
if (-not ([IntPtr]::Size -eq 8))
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
#endregion Preparation

#region Begin
# Сlear $Error variable
# Очистка переменной $Error
$Error.Clear()
# Checking the file encoding if it runs locally
# Проверка кодировки файла, если он запускается локально
if ($PSCommandPath)
{
	[System.IO.FileInfo]$script = Get-Item -Path $PSCommandPath
	$SequenceBOM = New-Object System.Byte[] 3
	$reader = $script.OpenRead()
	$bytesRead = $reader.Read($SequenceBOM, 0, 3)
	$reader.Dispose()
	if ($bytesRead -eq 3 -and $SequenceBOM[0] -ne 239 -and $SequenceBOM[1] -ne 187 -and $SequenceBOM[2] -ne 191)
	{
		if ($RU)
		{
			Write-Warning -Message "Файл не был сохранен в кодировке `"UTF-8 с BOM`""
		}
		else
		{
			Write-Warning -Message "The file wasn't saved in `"UTF-8 with BOM`" encoding"
		}
		break
	}
}
# Set the encoding to UTF-8 without BOM for the PowerShell session
# Установить кодировку UTF-8 без BOM для текущей сессии PowerShell
if ($RU)
{
	ping.exe | Out-Null
	$OutputEncoding = [System.Console]::OutputEncoding = [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
}
#endregion Begin

#region Privacy & Telemetry
# Turn off "Diagnostics Tracking Service"
# Отключить службу "Diagnostics Tracking Service"
Get-Service -ServiceName DiagTrack | Stop-Service
Get-Service -ServiceName DiagTrack | Set-Service -StartupType Disabled
# Stop event trace sessions
# Остановить сеансы отслеживания событий
logman.exe stop DiagLog -ets
logman.exe stop Diagtrack-Listener -ets
logman.exe stop SQMLogger -ets
# Turn off the data collectors at the next computer restart
# Отключить сборщики данных при следующем запуске ПК
REG add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener /v Start /t REG_DWORD /d 0 /f
REG add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog /v Start /t REG_DWORD /d 0 /f
REG add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger /v Start /t REG_DWORD /d 0 /f
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
Remove-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name PeriodInNanoSeconds -Force -ErrorAction Ignore
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
# Set File Explorer to open to This PC by default
# Открывать "Этот компьютер" в Проводнике
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force
# Show hidden files, folders, and drives
# Показывать скрытые файлы, папки и диски
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 1 -Force
# Turn off check boxes to select items
# Отключить флажки для выбора элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 0 -Force
# Show file name extensions
# Показывать расширения для зарегистрированных типов файлов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force
# Show folder merge conflicts
# Не скрывать конфликт слияния папок
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -PropertyType DWord -Value 0 -Force
# Do not show all folders in the navigation pane
# Не отображать все папки в области навигации
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name NavPaneShowAllFolders -PropertyType DWord -Value 0 -Force
# Show more details in file transfer dialog
# Развернуть диалог переноса файлов
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force
# Show the Ribbon expanded in File Explorer
# Отображать ленту проводника в развернутом виде
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Name MinimizedStateTabletModeOff -PropertyType DWord -Value 0 -Force
# Turn on recycle bin files delete confirmation
# Запрашивать подтверждение на удаление файлов в корзину
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ConfirmFileDelete -PropertyType DWord -Value 1 -Force
# Turn off the "- Shortcut" name extension for new shortcuts
# He дoбaвлять "- яpлык" для coздaвaeмыx яpлыкoв
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name link -PropertyType Binary -Value ([byte[]](00,00,00,00)) -Force
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
$unpin = [WinAPI.GetStr]::GetString(5387)
$apps = (New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
$apps | Where-Object -FilterScript {$_.Path -eq "Microsoft.InternetExplorer.Default"} | ForEach-Object -Process {$_.Verbs() | Where-Object -FilterScript {$_.Name -eq $unpin} | ForEach-Object -Process {$_.DoIt()}}
# Set the "Control Panel" view on "Large icons"
# Установить крупные значки в Панели управления
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 1 -Force
# Не отображать экран блокировки
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -PropertyType DWord -Value 1 -Force
# Do not show "New App Installed" notification
# Не показывать уведомление "Установлено новое приложение"
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -PropertyType DWord -Value 1 -Force
# Turn off JPEG desktop wallpaper import quality reduction
# Отключить снижение качества фона рабочего стола в формате JPEG
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force
# Turn off the "Previous Versions" tab from properties context menu
# Отключить вкладку "Предыдущие версии" в свойствах файлов и папок
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -PropertyType DWord -Value 1 -Force
# Unpin Microsoft Store from taskbar
# Открепить значок Магазина на панели задач
if (-not (Test-Path -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoPinningStoreToTaskbar -PropertyType DWord -Value 1 -Force
#endregion UI & Personalization

#region System
# Turn off AutoPlay for all media and devices
# Отключить автозапуск для всех носителей и устройств
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 1 -Force
# Make the "Open", "Print", "Edit" context menu items available, when more than 15 selected
# Сделать доступными элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -PropertyType DWord -Value 300 -Force
# Turn off hibernate
# Отключить гибридный спящий режим
New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\Power -Name HibernateEnabled -PropertyType DWord -Value 0 -Force
# Always wait for the network at computer startup and logon
# Всегда ждать сеть при запуске и входе в систему
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -PropertyType DWord -Value 1 -Force
# Do not preserve zone information
# Не хранить сведения о зоне происхождения вложенных файлов
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force
# Turn off Admin Approval Mode for administrators
# Отключить использование режима одобрения администратором для встроенной учетной записи администратора
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWord -Value 0 -Force
# Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
# Включить доступ к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -PropertyType DWord -Value 1 -Force
# Do not show user first sign-in animation
# Не показывать анимацию при первом входе в систему
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -PropertyType DWord -Value 0 -Force
# Turn off sticky Shift key after pressing 5 times
# Отключить залипание клавиши Shift после 5 нажатий
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force
# Change $env:TEMP environment variable path to $env:SystemDrive\Temp
# Изменить путь переменной среды для временных файлов на $env:SystemDrive\Temp
if (-not (Test-Path -Path $env:SystemDrive\Temp))
{
	New-Item -Path $env:SystemDrive\Temp -ItemType Directory -Force
}
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "User")
New-ItemProperty -Path HKCU:\Environment -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "User")
New-ItemProperty -Path HKCU:\Environment -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Process")
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Process")
Remove-Item $env:LOCALAPPDATA\Temp -Recurse -Force -ErrorAction Ignore
Restart-Service -Name Spooler -Force
Remove-Item -Path $env:SystemRoot\Temp -Recurse -Force -ErrorAction Ignore
# Turn off Windows features
# Отключить компоненты
$features = @(
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
Disable-WindowsOptionalFeature -Online -FeatureName $features -NoRestart
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
# Turn on updates for other Microsoft products
# Включить автоматическое обновление для других продуктов Microsoft
(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
# Set power management scheme for desktop and laptop
# Установить схему управления питания для стационарного ПК и ноутбука
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
{
	# High performance for desktop
	# Высокая производительность для стационарного ПК
	powercfg /setactive SCHEME_MIN
}
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 2)
{
	# Balanced for laptop
	# Сбалансированная для ноутбука
	powercfg /setactive SCHEME_BALANCED
}
# Turn on latest installed .NET runtime for all apps
# Использовать последнюю установленную версию .NET для всех приложений
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -PropertyType DWord -Value 1 -Force
# Turn on Num Lock at startup
# Включить Num Lock при загрузке
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483650 -Force
# Turn off F1 Help key
# Отключить справку по нажатию F1
if (-not (Test-Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
{
	New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -PropertyType String -Value "" -Force
# Show Task manager details
# Раскрыть окно Диспетчера задач
$taskmgr = Get-Process -Name Taskmgr -ErrorAction Ignore
if ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
Start-Process -FilePath .\Taskmgr
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
# Do not allow the computer to turn off the network adapters to save power
# Запретить отключение сетевых адаптеров для экономии энергии
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
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
#if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"))
#{
#	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Force
#}
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name BlockUserInputMethodsForSignIn -PropertyType DWord -Value 1 -Force
#New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 1 -PropertyType String -Value 00000409 -Force
#New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 2 -PropertyType String -Value 00000419 -Force
# Remove printers
# Удалить принтеры
Remove-Printer -Name Fax, "Microsoft XPS Document Writer" -ErrorAction Ignore
# Add "Run as different user" from context menu for .exe file type
# Добавить "Запуск от имени другого пользователя" в контекстное меню для .exe файлов
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name "(default)" -PropertyType String -Value "@shell32.dll,-50944" -Force
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force -ErrorAction Ignore
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name SuppressionPolicyEx -PropertyType String -Value "{F211AA05-D4DF-4370-A2A0-9F19C09756A7}" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser\command -Name DelegateExecute -PropertyType String -Value "{ea72d00e-4960-42fa-ba92-7792a7944c1d}" -Force
# Turn on Win32 long paths
# Включить длинные пути Win32
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force
# Turn off thumbnail cache removal
# Отключить удаление кэша миниатюр
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force
# Set location of the "Desktop", "Documents", "Downloads", "Music", "Pictures", and "Videos"
# Переопределить расположение папок "Рабочий стол", "Документы", "Загрузки", "Музыка", "Изображения", "Видео"
Function KnownFolderPath
{
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
		[string]$KnownFolder,

		[Parameter(Mandatory = $true)]
		[string]$Path
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
$drives = (Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Get-Partition | Get-Volume).DriveLetter
if ($RU)
{
	$OFS = ", "
	Write-Host "`nВаши диски: " -NoNewline
	Write-Host "$($drives | Sort-Object -Unique)" -ForegroundColor Yellow
	$OFS = " "
}
else
{
	$OFS = ", "
	Write-Host "`nYour drives: " -NoNewline
	Write-Host "$($drives | Sort-Object -Unique)" -ForegroundColor Yellow
	$OFS = " "
}
# Desktop
# Рабочий стол
if ($RU)
{
	Write-Host "`nВведите букву диска, в корне которого будет создана папка для " -NoNewline
	Write-Host "`"Рабочий стол`"" -ForegroundColor Yellow
	Write-Host "Файлы не будут перенесены: сделайте это вручную"
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType the drive letter in the root of which the " -NoNewline
	Write-Host "`"Desktop`" " -ForegroundColor Yellow -NoNewline
	Write-Host "folder will be created."
	Write-Host "Files will not be moved. Do it manually"
	Write-Host "`nPress Enter to skip" -NoNewline
}
do
{
	$drive = Read-Host -Prompt " "
	if ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$DesktopFolder = "${drive}:\Desktop"
		$DesktopReg = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop).Desktop
		if ($DesktopReg -ne $DesktopFolder)
		{
			if (-not (Test-Path -Path $DesktopFolder))
			{
				New-Item -Path $DesktopFolder -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Desktop -Path $DesktopFolder
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}" -PropertyType ExpandString -Value $DesktopFolder -Force
			Set-Content -Path "$DesktopFolder\desktop.ini" -Value $DesktopINI["Desktop"] -Encoding Unicode -Force
			(Get-Item -Path "$DesktopFolder\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$DesktopFolder\desktop.ini" -Force).Refresh()
		}
		# Save screenshots by pressing Win+PrtScr to the Desktop
		# Сохранить скриншот по Win+PrtScr на рабочем столе
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{b7bede81-df94-4682-a7d8-57a52620b86f}" -Name RelativePath -PropertyType String -Value $DesktopFolder -Force
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		if ($RU)
		{
			Write-Host "`nДиск $(${drive}.ToUpper()): не существует. " -ForegroundColor Yellow -NoNewline
			Write-Host "Введите букву диска."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "The disk $(${drive}.ToUpper()): does not exist. " -ForegroundColor Yellow -NoNewline
			Write-Host "Type the drive letter."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
until ($drives -eq $drive)
# Documents
# Документы
if ($RU)
{
	Write-Host "`nВведите букву диска, в корне которого будет создана папка для " -NoNewline
	Write-Host "`"Документы`"" -ForegroundColor Yellow
	Write-Host "Файлы не будут перенесены: сделайте это вручную"
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType the drive letter in the root of which the " -NoNewline
	Write-Host "`"Documents`" " -ForegroundColor Yellow -NoNewline
	Write-Host "folder will be created."
	Write-Host "Files will not be moved. Do it manually"
	Write-Host "`nPress Enter to skip" -NoNewline
}
do
{
	$drive = Read-Host -Prompt " "
	if ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$DocumentsFolder = "${drive}:\Documents"
		$DocumentsReg = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Personal).Personal
		if ($DocumentsReg -ne $DocumentsFolder)
		{
			if (-not (Test-Path -Path $DocumentsFolder))
			{
				New-Item -Path $DocumentsFolder -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Documents -Path $DocumentsFolder
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" -PropertyType ExpandString -Value $DocumentsFolder -Force
			Set-Content -Path "$DocumentsFolder\desktop.ini" -Value $DesktopINI["Documents"] -Encoding Unicode -Force
			(Get-Item -Path "$DocumentsFolder\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$DocumentsFolder\desktop.ini" -Force).Refresh()
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		if ($RU)
		{
			Write-Host "`nДиск $(${drive}.ToUpper()): не существует. " -ForegroundColor Yellow -NoNewline
			Write-Host "Введите букву диска."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "The disk $(${drive}.ToUpper()): does not exist. " -ForegroundColor Yellow -NoNewline
			Write-Host "Type the drive letter."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
until ($drives -eq $drive)
# Downloads
# Загрузки
if ($RU)
{
	Write-Host "`nВведите букву диска, в корне которого будет создана папка для " -NoNewline
	Write-Host "`"Загрузки`"" -ForegroundColor Yellow
	Write-Host "Файлы не будут перенесены: сделайте это вручную"
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType the drive letter in the root of which the " -NoNewline
	Write-Host "`"Downloads`" " -ForegroundColor Yellow -NoNewline
	Write-Host "folder will be created."
	Write-Host "Files will not be moved. Do it manually"
	Write-Host "`nPress Enter to skip" -NoNewline
}
do
{
	$drive = Read-Host -Prompt " "
	if ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$DownloadsFolder = "${drive}:\Downloads"
		$DownloadsReg = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}")."{374DE290-123F-4565-9164-39C4925E467B}"
		if ($DownloadsReg -ne $DownloadsFolder)
		{
			if (-not (Test-Path -Path $DownloadsFolder))
			{
				New-Item -Path $DownloadsFolder -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Downloads -Path $DownloadsFolder
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}" -PropertyType ExpandString -Value $DownloadsFolder -Force
			Set-Content -Path "$DownloadsFolder\desktop.ini" -Value $DesktopINI["Downloads"] -Encoding Unicode -Force
			(Get-Item -Path "$DownloadsFolder\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$DownloadsFolder\desktop.ini" -Force).Refresh()
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		if ($RU)
		{
			Write-Host "`nДиск $(${drive}.ToUpper()): не существует. " -ForegroundColor Yellow -NoNewline
			Write-Host "Введите букву диска."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "The disk $(${drive}.ToUpper()): does not exist. " -ForegroundColor Yellow -NoNewline
			Write-Host "Type the drive letter."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
until ($drives -eq $drive)
# Music
# Музыка
if ($RU)
{
	Write-Host "`nВведите букву диска, в корне которого будет создана папка для " -NoNewline
	Write-Host "`"Музыка`"" -ForegroundColor Yellow
	Write-Host "Файлы не будут перенесены: сделайте это вручную"
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType the drive letter in the root of which the " -NoNewline
	Write-Host "`"Music`" " -ForegroundColor Yellow -NoNewline
	Write-Host "folder will be created."
	Write-Host "Files will not be moved. Do it manually"
	Write-Host "`nPress Enter to skip" -NoNewline
}
do
{
	$drive = Read-Host -Prompt " "
	if ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$MusicFolder = "${drive}:\Music"
		$MusicReg = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Music")."My Music"
		if ($MusicReg -ne $MusicFolder)
		{
			if (-not (Test-Path -Path $MusicFolder))
			{
				New-Item -Path $MusicFolder -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Music -Path $MusicFolder
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{A0C69A99-21C8-4671-8703-7934162FCF1D}" -PropertyType ExpandString -Value $MusicFolder -Force
			Set-Content -Path "$MusicFolder\desktop.ini" -Value $DesktopINI["Music"] -Encoding Unicode -Force
			(Get-Item -Path "$MusicFolder\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$MusicFolder\desktop.ini" -Force).Refresh()
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		if ($RU)
		{
			Write-Host "`nДиск $(${drive}.ToUpper()): не существует. " -ForegroundColor Yellow -NoNewline
			Write-Host "Введите букву диска."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "The disk $(${drive}.ToUpper()): does not exist. " -ForegroundColor Yellow -NoNewline
			Write-Host "Type the drive letter."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
until ($drives -eq $drive)
# Pictures
# Изображения
if ($RU)
{
	Write-Host "`nВведите букву диска, в корне которого будет создана папка для " -NoNewline
	Write-Host "`"Изображения`"" -ForegroundColor Yellow
	Write-Host "Файлы не будут перенесены: сделайте это вручную"
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType the drive letter in the root of which the " -NoNewline
	Write-Host "`"Pictures`" " -ForegroundColor Yellow -NoNewline
	Write-Host "folder will be created."
	Write-Host "Files will not be moved. Do it manually"
	Write-Host "`nPress Enter to skip" -NoNewline
}
do
{
	$drive = Read-Host -Prompt " "
	if ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$PicturesFolder = "${drive}:\Pictures"
		$PicturesReg = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Pictures")."My Pictures"
		if ($PicturesReg -ne $PicturesFolder)
		{
			if (-not (Test-Path -Path $PicturesFolder))
			{
				New-Item -Path $PicturesFolder -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Pictures -Path $PicturesFolder
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{0DDD015D-B06C-45D5-8C4C-F59713854639}" -PropertyType ExpandString -Value $PicturesFolder -Force
			Set-Content -Path "$PicturesFolder\desktop.ini" -Value $DesktopINI["Pictures"] -Encoding Unicode -Force
			(Get-Item -Path "$PicturesFolder\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$PicturesFolder\desktop.ini" -Force).Refresh()
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		if ($RU)
		{
			Write-Host "`nДиск $(${drive}.ToUpper()): не существует. " -ForegroundColor Yellow -NoNewline
			Write-Host "Введите букву диска."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "`nThe disk $(${drive}.ToUpper()): does not exist. " -ForegroundColor Yellow -NoNewline
			Write-Host "Type the drive letter."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
until ($drives -eq $drive)
# Videos
# Видео
if ($RU)
{
	Write-Host "`nВведите букву диска, в корне которого будет создана папка для " -NoNewline
	Write-Host "`"Видео`"" -ForegroundColor Yellow
	Write-Host "Файлы не будут перенесены: сделайте это вручную"
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType the drive letter in the root of which the " -NoNewline
	Write-Host "`"Videos`" " -ForegroundColor Yellow -NoNewline
	Write-Host "folder will be created."
	Write-Host "Files will not be moved. Do it manually"
	Write-Host "`nPress Enter to skip" -NoNewline
}
do
{
	$drive = Read-Host -Prompt " "
	if ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$VideosFolder = "${drive}:\Videos"
		$VideosReg = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Video")."My Video"
		if ($VideosReg -ne $VideosFolder)
		{
			if (-not (Test-Path -Path $VideosFolder))
			{
				New-Item -Path $VideosFolder -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Videos -Path $VideosFolder
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" -PropertyType ExpandString -Value $VideosFolder -Force
			Set-Content -Path "$VideosFolder\desktop.ini" -Value $DesktopINI["Videos"] -Encoding Unicode -Force
			(Get-Item -Path "$VideosFolder\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
			(Get-Item -Path "$VideosFolder\desktop.ini" -Force).Refresh()
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		if ($RU)
		{
			Write-Host "`nДиск $(${drive}.ToUpper()): не существует. " -ForegroundColor Yellow -NoNewline
			Write-Host "Введите букву диска."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "`nThe disk $(${drive}.ToUpper()): does not exist. " -ForegroundColor Yellow -NoNewline
			Write-Host "Type the drive letter."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
until ($drives -eq $drive)
#endregion System

#region Context menu
# Turn off "Look for an app in the Microsoft Store" in "Open with" dialog
# Отключить "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью"
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force
# Add "Extract" to MSI file type context menu
# Добавить пункт "Extract" для MSI в контекстное меню
if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force
}
$Value = "{0}" -f 'msiexec.exe /a "%1" /qb TARGETDIR="%1 extracted"'
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(default)" -PropertyType String -Value $Value -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-31382" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force
# Remove "Send to" from folder context menu
# Удалить пункт "Отправить" из контекстного меню папки
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(Default)" -PropertyType String -Value "" -Force
# Remove "Turn on BitLocker" from context menu
# Удалить пункт "Включить Bitlocker" из контекстного меню
if (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -eq "Professional" -or $_.Edition -eq "Enterprise"})
{
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\manage-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\unlock-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}
# Remove "Include in Library" from context menu
# Удалить пункт "Добавить в библиотеку" из контекстного меню
New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(default)" -PropertyType String -Value "-{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force
# Remove "Pin to Start" from .exe files context menu
# Удалить пункт "Закрепить на начальном экране" из контекстного меню для .exe-файлов
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen -Force -ErrorAction Ignore
# Remove "Pin to Start" from folders context menu
# Удалить пункт "Закрепить на начальном экране" из контекстного меню папок
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen -Force -ErrorAction Ignore
# Remove "Contact" from context menu
# Удалить пункт "Контакт" из контекстного меню
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.contact\ShellNew -Force -ErrorAction Ignore
# Remove "Compressed (zipped) Folder" from context menu
# Удалить пункт "Сжатая ZIP-папка" из контекстного меню
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Force -ErrorAction Ignore
# Remove "Print" from batch and .cmd files context menu
# Удалить пункт "Печать" из контекстного меню для .bat и .cmd файлов
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
# Remove "Rich Text Document" from context menu
# Удалить пункт "Создать Документ в формате RTF" из контекстного меню
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Force -ErrorAction Ignore
# Remove "Bitmap image" from context menu
# Удалить пункт "Создать Точечный рисунок" из контекстного меню
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Force -ErrorAction Ignore
#endregion Context menu

#region OneDrive
# Turn off OneDrive
# Отключить OneDrive
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -PropertyType DWord -Value 1 -Force
Get-ScheduledTask -TaskName "Routine Maintenance Task", "Idle Sync Maintenance Task" | Disable-ScheduledTask
#endregion OneDrive

#region Windows Defender & Security
# Turn off SmartScreen for apps and files
# Отключить SmartScreen для приложений и файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force
# Turn off Windows Script Host
# Отключить Windows Script Host
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -PropertyType DWord -Value 0 -Force
# Add exclusion folder from Windows Defender Antivirus scanning
# Добавить в исключение Windows Defender папку
# https://yamanxworld.blogspot.com/2017/05/windows-81-windows-defender.html
$file = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1"
cmd.exe --% /c "takeown /F %WINDIR%\system32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1"
cmd.exe --% /c "icacls %WINDIR%\system32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1 /grant:r %USERNAME%:F"
(Get-Content -Path $file) | ForEach-Object -Process {
	$_.replace("'MSFT_MpSignature.cdxml',", "'MSFT_MpSignature.cdxml')").
	replace("'Remove-MpThreat',", "'Remove-MpThreat')")
} | Set-Content -Path $file
(Get-Content -Path $file | Select-String -Pattern "MSFT_MpWDOScan.cdxml" -NotMatch) | Set-Content -Path $file -Force
(Get-Content -Path $file | Select-String -Pattern "Start-MpScan" -NotMatch) | Set-Content -Path $file -Force
(Get-Content -Path $file | Select-String -Pattern "Start-MpWDOScan" -NotMatch) | Set-Content -Path $file -Force
if ($RU)
{
	Write-Host "`nВведите полные пути до файлов или папок, которые следует "
	Write-Host "исключить из списка сканирования Microsoft Defender."
	Write-Host "Пути должны быть разделены запятыми и взяты в кавычки." -ForegroundColor Yellow
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType the full paths to files or folders, which to exclude "
	Write-Host "from Microsoft Defender Antivirus Scan."
	Write-Host "The paths must be separated by commas and taken in quotes." -ForegroundColor Yellow
	Write-Host "`nPress Enter to skip" -NoNewline
}
function ExclusionPath
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $True)]
		[string[]]$paths
	)
	$paths = $paths.Replace("`"", "").Split(",").Trim()
	Add-MpPreference -ExclusionPath $paths -Force
}
do
{
	$paths = Read-Host -Prompt " "
	if ($paths -match "`"")
	{
		ExclusionPath $paths
	}
	elseif ([string]::IsNullOrEmpty($paths))
	{
		break
	}
	else
	{
		Write-Host "`nThe paths hasn't been taken in quotes." -ForegroundColor Yellow
		Write-Host "Type the paths by quoting and separating by commas."
		Write-Host "`nPress Enter to skip" -NoNewline
	}
}
until ($paths -match "`"")
#endregion Windows Defender & Security

#region UWP apps
# Uninstall all UWP apps from all accounts
# Удалить все UWP-приложения из всех учетных записей
Get-AppxPackage -AllUsers | Remove-AppxPackage -ErrorAction Ignore
# Uninstall all provisioned UWP apps from all accounts except
# Удалить все UWP-приложения из системной учетной записи
Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online -ErrorAction Ignore
#endregion UWP apps

#region Scheduled tasks
# Create a task in the Task Scheduler to start cleaning up Windows updates
# The task runs every 90 days
# Создать задачу в Планировщике задач по очистке обновлений Windows
# Задача выполняется каждые 90 дней
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name StateFlags1337 -PropertyType DWord -Value 2 -Force
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cleanmgr.exe" -Argument "/sagerun:1337"
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 90 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
	"TaskName"	= "Update Cleanup"
	"Action"	= $action
	"Trigger"	= $trigger
	"Settings"	= $settings
}
Register-ScheduledTask @Params -User $env:USERNAME -RunLevel Highest -Force
# Create a task in the Task Scheduler to clear the $env:TEMP folder
# The task runs every 62 days
# Создать задачу в Планировщике задач по очистке папки $env:TEMP
# Задача выполняется каждые 62 дня
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	Get-ChildItem -Path `$env:TEMP -Force -Recurse | Remove-Item -Force -Recurse
"@
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 62 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
	"TaskName"	= "Temp"
	"Action"	= $action
	"Trigger"	= $trigger
	"Settings"	= $settings
}
Register-ScheduledTask @Params -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force
# Create a task in the Task Scheduler to clear the $env:SystemRoot\SoftwareDistribution\Download folder
# The task runs on Thursdays every 4 weeks
# Создать задачу в Планировщике задач по очистке папки $env:SystemRoot\SoftwareDistribution\Download
# Задача выполняется по четвергам каждую 4 неделю
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	`$getservice = Get-Service -Name wuauserv
	`$getservice.WaitForStatus('Stopped', '01:00:00')
	Get-ChildItem -Path `$env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
"@
$trigger = New-JobTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Thursday -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
	"TaskName"	= "SoftwareDistribution"
	"Action"	= $action
	"Trigger"	= $trigger
	"Settings"	= $settings
}
Register-ScheduledTask @Params -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force
# Create a task in the Task Scheduler to clear the "$env:SystemRoot\LiveKernelReports" folder.
# The task runs every 62 days
# Создать задачу в Планировщике задач по очистке папки "$env:SystemRoot\LiveKernelReports"
# Задача выполняется каждые 62 дня
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
`$dir = '$env:SystemRoot\LiveKernelReports'
`$foldersize = (Get-ChildItem -Path `$dir -Recurse | Measure-Object -Property Length -Sum).Sum/1MB
if (`$foldersize -gt 100)
{
	Get-ChildItem -Path `$dir -Recurse -Force | Remove-Item -Recurse -Force
}
"@
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 62 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
	"TaskName"	= "LiveKernelReports"
	"Action"	= $action
	"Trigger"	= $trigger
	"Settings"	= $settings
}
Register-ScheduledTask @Params -User System -RunLevel Highest -Force
# Create a task in the Task Scheduler to clear the "$env:SystemRoot\Logs\CBS" folder.
# The task runs every 62 days
# Создать задачу в Планировщике задач по очистке папки "$env:SystemRoot\Logs\CBS"
# Задача выполняется каждые 62 дня
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	`$dir = '$env:SystemRoot\Logs\CBS'
	`$foldersize = (Get-ChildItem -Path `$dir -Recurse | Measure-Object -Property Length -Sum).Sum/1MB
	if (`$foldersize -GT 10)
	{
		Get-ChildItem -Path `$dir -Recurse -Force | Remove-Item -Recurse -Force
	}
"@
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 62 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
	"TaskName"	= "CBS"
	"Action"	= $action
	"Trigger"	= $trigger
	"Settings"	= $settings
}
Register-ScheduledTask @Params -User System -RunLevel Highest -Force
#endregion Scheduled tasks

#region End
# Refresh desktop icons, environment variables and taskbar without restarting File Explorer
# Обновить иконки рабочего стола, переменные среды и панель задач без перезапуска "Проводника"
$UpdateEnvExplorerAPI = @{
	Namespace = "WinAPI"
	Name = "UpdateEnvExplorer"
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
			SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
			// Update environment variables
			SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, null, SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
			// Update taskbar
			SendNotifyMessage(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings");
		}
"@
}
if (-not ("WinAPI.UpdateEnvExplorer" -as [type]))
{
	Add-Type @UpdateEnvExplorerAPI
}
[WinAPI.UpdateEnvExplorer]::Refresh()

# Errors output
# Вывод ошибок
if ($Error)
{
	Write-Host "`nWarnings/Errors" -BackgroundColor Red
	($Error | ForEach-Object -Process {
		[PSCustomObject] @{
			Line = $_.InvocationInfo.ScriptLineNumber
			Error = $_.Exception.Message
		}
	} | Sort-Object -Property Line | Format-Table -AutoSize -Wrap | Out-String).Trim()
}
#endregion End