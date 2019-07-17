# Сlear $Error
# Очистка $Error
$Error.Clear()
# Отключить службы диагностического отслеживания
Get-Service -ServiceName DiagTrack | Stop-Service
Get-Service -ServiceName DiagTrack | Set-Service -StartupType Disabled
# Отключить отчеты об ошибках Windows
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Value 1 -Force
# Изменить частоту формирования отзывов на "Никогда"
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Siuf\Rules))
{
	New-Item -Path HKCU:\Software\Microsoft\Siuf\Rules -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -Value 0 -Force
Remove-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name PeriodInNanoSeconds -Force -ErrorAction SilentlyContinue
# Отключить задачи диагностического отслеживания в Планировщике задач
Unregister-ScheduledTask -TaskName "Optimize Start Menu*" -Confirm:$false
$tasks = @(
	"AitAgent",
	"BackupTask",
	"BthSQM",
	"Consolidator",
	"FamilySafetyMonitor",
	"FamilySafetyRefresh",
	"FamilySafetyUpload",
	"File History (maintenance mode)",
	"GatherNetworkInfo",
	"Idle Sync Maintenance Task",
	"KernelCeipTask",
	"Microsoft Compatibility Appraiser",
	"Microsoft-Windows-DiskDiagnosticDataCollector",
	"MNO Metadata Parser",
	"NetworkStateChangeTask",
	"ProgramDataUpdater",
	"Proxy",
	"QueueReporting",
	"Routine Maintenance Task",
	"SmartScreenSpecific",
	"StartupAppTask",
	"UsbCeip",
	"WinSAT",
	"SqmUpload_*")
Foreach ($task in $tasks)
{
	Get-ScheduledTask -TaskName $task | Disable-ScheduledTask
}
# Отключить в "Журналах Windows/Безопасность" сообщения "Платформа фильтрации IP-пакетов Windows разрешила подключение"
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
# Отобразить "Этот компьютер" на Рабочем столе
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Force
# Показывать скрытые файлы
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Value 1 -Force
# Открывать "Этот компьютер" в Проводнике
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1 -Force
# Показывать расширения файлов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0 -Force
# Не скрывать конфликт слияния папок
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -Value 0 -Force
# Отключить флажки для выбора элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -Value 0 -Force
# Не отображать все папки в области навигации
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name NavPaneShowAllFolders -Value 0 -Force
# Развернуть диалог переноса файлов
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -Value 1 -Force
# Отключить автозапуск с внешних носителей
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -Value 1 -Force
# He дoбaвлять "- яpлык" для coздaвaeмыx яpлыкoв
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name link -PropertyType Binary -Value ([byte[]](00,00,00,00)) -Force
# Всегда отображать все значки в области уведомлений
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -Value 0 -Force
# Установка крупных значков в панели управления
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -Value 1 -Force
# Снятие ограничения на одновременное открытие более 15 элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -Value 300 -Force
# Отключить гибридный спящий режим
New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\Power -Name HibernateEnabled -Value 0 -Force
# Не отображать экран блокировки
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Value 1 -Force
# Включить отображение ленты проводника в развернутом виде
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Name MinimizedStateTabletModeOff -Value 0 -Force
# Отключить поиск программ в Microsoft Store
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Value 1 -Force
# Не показывать уведомление "Установлено новое приложение"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -Value 1 -Force
# Отключить OneDrive
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Value 1 -Force
# Всегда ждать сеть при запуске и входе в систему
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -Value 1 -Force
# Запрашивать подтверждение при удалении файлов
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ConfirmFileDelete -Value 1 -Force
# Не хранить сведения о зоне происхождения вложенных файлов
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Value 1 -Force
# Отключить использование режима одобрения администратором для встроенной учетной записи администратора
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0 -Force
# Включить доступ к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -Value 1 -Force
# Не показывать анимацию при первом входе в систему
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -Value 0 -Force
# Отключить SmartScreen для приложений и файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force
# Сохранять скриншот по Win+PrtScr на Рабочем столе
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{b7bede81-df94-4682-a7d8-57a52620b86f}" -Name RelativePath -PropertyType String -Value %USERPROFILE%\Desktop -Force
# Установка качества фона рабочего стола на 100 %
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -Value 100 -Force
# Отключить залипания клавиши Shift после 5 нажатий
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force
# Отключить отображение вкладки "Предыдущие версии" в свойствах файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -Value 1 -Force
# Изменить путь переменной среды для временных файлов
IF (-not (Test-Path -Path $env:SystemDrive\Temp))
{
	New-Item -Path $env:SystemDrive\Temp -ItemType Directory -Force
}
[Environment]::SetEnvironmentVariable("TMP","$env:SystemDrive\Temp","User")
New-ItemProperty -Path HKCU:\Environment -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TEMP","$env:SystemDrive\Temp","User")
New-ItemProperty -Path HKCU:\Environment -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TMP","$env:SystemDrive\Temp","Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TEMP","$env:SystemDrive\Temp","Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TMP","$env:SystemDrive\Temp",'Process')
[Environment]::SetEnvironmentVariable("TEMP","$env:SystemDrive\Temp",'Process')
# Удалить UWP-приложения
Get-AppxPackage -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
# Отключить компоненты
$features = @(
	# Отключить службу "Факсы и сканирование"
	"FaxServicesClientPackage",
	# Отключить компоненты прежних версий
	"LegacyComponents",
	# Отключение компонентов работы с мультимедиа
	"MediaPlayback",
	# Отключить PowerShell 2.0
	"MicrosoftWindowsPowerShellV2",
	"MicrosoftWindowsPowershellV2Root",
	# Отключить службу XPS
	"Printing-XPSServices-Features",
	# Отключить службу "Клиент рабочих папок"
	"WorkFolders-Client",
	# Отключить просмотрщик XPS
	"Xps-Foundation-Xps-Viewer")
Foreach ($feature in $features)
{
	Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
}
# Добавить Средство просмотра фотографий Windows в пункт контекстного меню "Открыть с помощью"
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open -Name MuiVerb -PropertyType String -Value "@photoviewer.dll,-3043" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\command -Name "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\DropTarget -Name Clsid -PropertyType String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\print\command -Name "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\DropTarget -Name Clsid -PropertyType String -Value "{60fd46de-f830-4894-a628-6fa81bc0190d}" -Force
# Ассоциация со Средством просмотра фотографий Windows
cmd.exe /c --% ftype Paint.Picture=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1
cmd.exe /c --% ftype jpegfile=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1
cmd.exe /c --% ftype pngfile=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1
cmd.exe /c --% ftype TIFImage.Document=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1
cmd.exe /c assoc .bmp=Paint.Picture
cmd.exe /c assoc .jpg=jpegfile
cmd.exe /c assoc .jpeg=jpegfile
cmd.exe /c assoc .png=pngfile
cmd.exe /c assoc .tif=TIFImage.Document
cmd.exe /c assoc .tiff=TIFImage.Document
cmd.exe /c assoc Paint.Picture\DefaultIcon=%SystemRoot%\System32\imageres.dll,-70
cmd.exe /c assoc jpegfile\DefaultIcon=%SystemRoot%\System32\imageres.dll,-72
cmd.exe /c assoc pngfile\DefaultIcon=%SystemRoot%\System32\imageres.dll,-71
cmd.exe /c assoc TIFImage.Document\DefaultIcon=%SystemRoot%\System32\imageres.dll,-122
# Включить автоматическое обновление для других продуктов Microsoft
(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
# Включить восстановление системы
Enable-ComputerRestore -Drive $env:SystemDrive
Get-ScheduledTask -TaskName SR | Enable-ScheduledTask
Get-Service -ServiceName swprv, vss | Set-Service -StartupType Manual
Get-Service -ServiceName swprv, vss | Start-Service
Get-CimInstance -ClassName Win32_ShadowCopy | Remove-CimInstance
# Отключить Windows Script Host
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Value 0 -Force
# Включить брандмауэр
Set-NetFirewallProfile -Enabled True
# Включить в Планировщике задач запуск очистки диска
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name StateFlags1337 -Value 2 -Force
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
# Включить в Планировщике задач очистки временной папки
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	Get-ChildItem -Path `$env:TEMP -Force -Recurse | Remove-Item -Force -Recurse
"@
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 61 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
	"TaskName"	= "Temp"
	"Action"	= $action
	"Trigger"	= $trigger
	"Settings"	= $settings
}
Register-ScheduledTask @Params -User System -RunLevel Highest -Force
# Включить в Планировщике задач очистку папки %SYSTEMROOT%\SoftwareDistribution\Download
$xml = 'Программы\Прочее\xml\SoftwareDistribution.xml'
function Get-ResolvedPath
{
	param (
		[Parameter(ValueFromPipeline = 1)]
		$Path
	)
	(Get-Disk | Where-Object -FilterScript {$_.BusType -eq "USB"} | Get-Partition | Get-Volume | Where-Object -FilterScript {$null -ne $_.DriveLetter}).DriveLetter | ForEach-Object -Process {Join-Path ($_ + ":") $Path -Resolve -ErrorAction SilentlyContinue}
}
$xml | Get-ResolvedPath | Get-Item | Get-Content -Raw | Register-ScheduledTask -TaskName "SoftwareDistribution" -Force
# Включить в Планировщике задач очистки папки %SYSTEMROOT%\LiveKernelReports
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
`$dir = '$env:SystemRoot\LiveKernelReports'
`$foldersize = (Get-ChildItem -Path `$dir -Recurse | Measure-Object -Property Length -Sum).Sum/1MB
IF (`$foldersize -GT 100)
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
# Включить в Планировщике задач очистки папки %SYSTEMROOT%\Logs\CBS
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	`$dir = '$env:SystemRoot\Logs\CBS'
	`$foldersize = (Get-ChildItem -Path `$dir -Recurse | Measure-Object -Property Length -Sum).Sum/1MB
	IF (`$foldersize -GT 10)
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
# Установить схему управления питания для стационарного ПК и ноутбука
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
{
	# High performance for desktop
	# Высокая производительность для стационарного ПК
	powercfg /setactive SCHEME_MIN
}
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 2)
{
	# Balanced for laptop
	# Сбалансированная для ноутбука
	powercfg /setactive SCHEME_BALANCED
}
# Использовать последнюю установленную версию .NET Framework для всех приложений
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Value 1 -Force
# Включить Num Lock при загрузке
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483650 -Force
# Добавить в исключение Windows Defender папку
$file = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1"
cmd.exe /c "takeown /F %WINDIR%\system32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1"
cmd.exe /c "icacls %WINDIR%\system32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1 /grant:r Администраторы:F"
(Get-Content $file) | ForEach-Object -Process {
	$_.replace("'MSFT_MpSignature.cdxml',", "'MSFT_MpSignature.cdxml')").
	replace("'MSFT_MpWDOScan.cdxml')", "").
	replace("'Remove-MpThreat',", "'Remove-MpThreat')").
	replace("'Start-MpWDOScan')", "")
} | Out-File $file
$drives = Get-Disk | Where-Object -FilterScript {$_.IsBoot -eq $false}
IF ($drives)
{
	$drives = ($drives | Get-Partition | Get-Volume | Where-Object -FilterScript {$null -ne $_.DriveLetter}).DriveLetter | ForEach-Object -Process {Join-Path ($_ + ":") $Path -Resolve -ErrorAction SilentlyContinue}
	Foreach ($drive in $drives)
	{
		$folder = "Программы\Прочее"
		Add-MpPreference -ExclusionPath (Join-Path -Path $drive -ChildPath $folder) -Force
	}
}
# Отключить справку по F1
IF (-not (Test-Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
{
	New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -PropertyType String -Value "" -Force
# Раскрыть окно Диспетчера задач
$taskmgr = Get-Process -Name Taskmgr -ErrorAction SilentlyContinue
IF ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
$taskmgr = Start-Process -FilePath taskmgr.exe -WindowStyle Hidden -PassThru
Do
{
	Start-Sleep -Milliseconds 100
	$preferences = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -ErrorAction SilentlyContinue
}
Until ($preferences)
Stop-Process $taskmgr
$preferences.Preferences[28] = 0
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -PropertyType Binary -Value $preferences.Preferences -Force
# Запретить отключение Ethernet-адаптера для экономии энергии
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
{
	$adapter = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement
	$adapter.AllowComputerToTurnOffDevice = "Disabled"
	$adapter | Set-NetAdapterPowerManagement
}
# Переопределить пользовательский метод ввода на английский язык на экране входа
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name BlockUserInputMethodsForSignIn -Value 1 -Force
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 1 -PropertyType String -Value 00000409 -Force
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 2 -PropertyType String -Value 00000419 -Force
# Открепить значок Магазина на панели задач
IF (-not (Test-Path -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoPinningStoreToTaskbar -Value 1 -Force
# Открепить Microsoft Edge от панели задач
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
IF (-not ("WinAPI.GetStr" -as [type]))
{
	Add-Type @Signature -Using System.Text
}
$unpin = [WinAPI.GetStr]::GetString(5387)
(New-Object -Com Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items() | ForEach-Object -Process {$_.Verbs() | Where-Object -FilterScript {$_.Name -eq $unpin} | ForEach-Object -Process {$_.DoIt()}}
# Добавить пункт "Extract" для MSI в контекстное меню
IF (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force
}
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(default)" -PropertyType String -Value 'msiexec.exe /a "%1" /qb TARGETDIR="%1 extracted"' -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-31382" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force
# Удалить принтеры
Remove-Printer -Name Fax, "Microsoft XPS Document Writer" -ErrorAction SilentlyContinue
# Добавить "Запуск от имени другого пользователя" в контекстное меню для exe-файлов
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name "(Default)" -PropertyType String -Value "@shell32.dll,-50944" -Force
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name SuppressionPolicyEx -PropertyType String -Value "{F211AA05-D4DF-4370-A2A0-9F19C09756A7}" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser\command -Name DelegateExecute -PropertyType String -Value "{ea72d00e-4960-42fa-ba92-7792a7944c1d}" -Force
# Включить длинные пути Win32
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1 -Force
# Отключить удаление кэша миниатюр
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -Value 0 -Force
# Удалить пункт "Отправить" из контекстного меню
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(Default)" -PropertyType String -Value "" -Force
# Удалить пункт "Включить Bitlocker" из контекстного меню
IF (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -eq "Professional" -or $_.Edition -eq "Enterprise"})
{
	$keys = @(
		"encrypt-bde",
		"encrypt-bde-elev",
		"manage-bde",
		"resume-bde",
		"resume-bde-elev",
		"unlock-bde")
	Foreach ($key in $keys)
	{
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\$key -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	}
}
# Удалить пункт "Добавить в библиотеку" из контекстного меню
Clear-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(default)" -Force
Clear-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(default)" -Force
# Удалить пункт "Закрепить на Начальном экране" из контекстного меню для .exe-файлов
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen -Force -ErrorAction SilentlyContinue
# Удалить пункт "Закрепить на Начальном экране" из контекстного меню
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen -Force -ErrorAction SilentlyContinue
# Удалить пункт "Создать контакт" из контекстного меню
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.contact\ShellNew -Name command -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.contact\ShellNew -Name iconpath -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.contact\ShellNew -Name MenuText -Force -ErrorAction SilentlyContinue
# Удалить пункт "Создать архив ZIP" из контекстного меню
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Name Data -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Name ItemName -Force -ErrorAction SilentlyContinue
# Удалить пункт "Печать" для bat- и cmd-файлов из контекстного меню
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Recurse -Force -ErrorAction SilentlyContinue
# Удалить пункт "Создать Документ в формате RTF" из контекстного меню
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Name Data -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Name ItemName -Force -ErrorAction SilentlyContinue
# Удалить пункт "Создать Точечный рисунок" из контекстного меню
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Name ItemName -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Name NullFile -Force -ErrorAction SilentlyContinue
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
	IF (-not ("WinAPI.KnownFolders" -as [type]))
	{
		Add-Type @Signature
	}
	foreach ($guid in $KnownFolders[$KnownFolder])
	{
		[WinAPI.KnownFolders]::SHSetKnownFolderPath([ref]$guid, 0, 0, $Path)
	}
	Attrib +r $Path
}
[hashtable] $desktopini = @{
	"Desktop"	=	'',
					'[.ShellClassInfo]','LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21769',
					'IconResource=%SystemRoot%\system32\imageres.dll,-183'
	"Documents"	=	'',
					'[.ShellClassInfo]','LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770',
					'IconResource=%SystemRoot%\system32\imageres.dll,-112','IconFile=%SystemRoot%\system32\shell32.dll',
					'IconIndex=-235'
	"Downloads"	=	'',
					'[.ShellClassInfo]','LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21798',
					'IconResource=%SystemRoot%\system32\imageres.dll,-184'
	"Music"		=	'',
					'[.ShellClassInfo]','LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21790',
					'InfoTip=@%SystemRoot%\system32\shell32.dll,-12689',
					'IconResource=%SystemRoot%\system32\imageres.dll,-108',
					'IconFile=%SystemRoot%\system32\shell32.dll','IconIndex=-237'
	"Pictures"	=	'',
					'[.ShellClassInfo]',
					'LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21779',
					'InfoTip=@%SystemRoot%\system32\shell32.dll,-12688',
					'IconResource=%SystemRoot%\system32\imageres.dll,-113',
					'IconFile=%SystemRoot%\system32\shell32.dll',
					'IconIndex=-236'
	"Videos"	=	'',
					'[.ShellClassInfo]',
					'LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21791',
					'InfoTip=@%SystemRoot%\system32\shell32.dll,-12690',
					'IconResource=%SystemRoot%\system32\imageres.dll,-189',
					'IconFile=%SystemRoot%\system32\shell32.dll','IconIndex=-238'
}
$drives = (Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Get-Partition | Get-Volume).DriveLetter
# Рабочий стол
Do
{
	$drive = Read-Host -Prompt "Type the drive letter in the root of which the `"Desktop`" folder will be created.
Press Enter to skip
`nВведите букву диска, в корне которого будет создана папка `"Рабочий стол`".
Чтобы пропустить, нажмите Enter"
	IF ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$regdesktop = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
		IF ($regdesktop -ne "${drive}:\Desktop")
		{
			IF (-not (Test-Path -Path "${drive}:\Desktop"))
			{
				New-Item -Path "${drive}:\Desktop" -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Desktop -Path "${drive}:\Desktop"
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}" -PropertyType ExpandString -Value "${drive}:\Desktop" -Force
			Set-Content -Path "${drive}:\Desktop\desktop.ini" -Value $desktopini["Desktop"] -Encoding Unicode -Force
			(Get-Item -Path "${drive}:\Desktop\desktop.ini").Attributes = "Hidden", "System", "Archive"
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		Read-Host -Prompt "`nThe disk does not exist. Press Enter to skip
`nДиск не существует. Введите букву диска.
Чтобы пропустить, нажмите Enter"
	}
}
Until ($drives -eq $drive)
# Документы
Do
{
	$drive = Read-Host -Prompt "Type the drive letter in the root of which the `"Documents`" folder will be created.
Press Enter to skip
`nВведите букву диска, в корне которого будет создана папка `"Документы`".
Чтобы пропустить, нажмите Enter"
	IF ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$regdocuments = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Personal
		IF ($regdocuments -ne "${drive}:\Documents")
		{
			IF (-not (Test-Path -Path "${drive}:\Documents"))
			{
				New-Item -Path "${drive}:\Documents" -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Documents -Path "${drive}:\Documents"
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" -PropertyType ExpandString -Value "${drive}:\Documents" -Force
			Set-Content -Path "${drive}:\Documents\desktop.ini" -Value $desktopini["Documents"] -Encoding Unicode -Force
			(Get-Item -Path "${drive}:\Documents\desktop.ini").Attributes = "Hidden", "System", "Archive"
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		Read-Host -Prompt "`nThe disk does not exist. Press Enter to skip
`nДиск не существует. Введите букву диска.
Чтобы пропустить, нажмите Enter"
	}
}
Until ($drives -eq $drive)
# Загрузки
Do
{
	$drive = Read-Host -Prompt "Type the drive letter in the root of which the `"Downloads`" folder will be created.
Press Enter to skip
`nВведите букву диска, в корне которого будет создана папка `"Загрузки`".
Чтобы пропустить, нажмите Enter"
	IF ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$regdownloads = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
		IF ($regdownloads -ne "${drive}:\Downloads")
		{
			IF (-not (Test-Path -Path "${drive}:\Downloads"))
			{
				New-Item -Path "${drive}:\Downloads" -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Downloads -Path "${drive}:\Downloads"
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}" -PropertyType ExpandString -Value "${drive}:\Downloads" -Force
			Set-Content -Path "${drive}:\Downloads\desktop.ini" -Value $desktopini["Downloads"] -Encoding Unicode -Force
			(Get-Item -Path "${drive}:\Downloads\desktop.ini").Attributes = "Hidden", "System", "Archive"
			# Edge
			$edge = (Get-AppxPackage "Microsoft.MicrosoftEdge").PackageFamilyName
			New-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\Main" -Name "Default Download Directory" -PropertyType String -Value "${drive}:\Downloads" -Force
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		Read-Host -Prompt "`nThe disk does not exist. Press Enter to skip
`nДиск не существует. Введите букву диска.
Чтобы пропустить, нажмите Enter"
	}
}
Until ($drives -eq $drive)
# Музыка
Do
{
	$drive = Read-Host -Prompt "Type the drive letter in the root of which the `"Music`" folder will be created.
Press Enter to skip
`nВведите букву диска, в корне которого будет создана папка `"Музыка`".
Чтобы пропустить, нажмите Enter"
	IF ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$regmusic = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Music"
		IF ($regmusic -ne "${drive}:\Music")
		{
			IF (-not (Test-Path -Path "${drive}:\Music"))
			{
				New-Item -Path "${drive}:\Music" -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Music -Path "${drive}:\Music"
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{A0C69A99-21C8-4671-8703-7934162FCF1D}" -PropertyType ExpandString -Value "${drive}:\Music" -Force
			Set-Content -Path "${drive}:\Music\desktop.ini" -Value $desktopini["Music"] -Encoding Unicode -Force
			(Get-Item -Path "${drive}:\Music\desktop.ini").Attributes = "Hidden", "System", "Archive"
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		Read-Host -Prompt "`nThe disk does not exist. Press Enter to skip
`nДиск не существует. Введите букву диска.
Чтобы пропустить, нажмите Enter"
	}
}
Until ($drives -eq $drive)
# Изображения
Do
{
	$drive = Read-Host -Prompt "Type the drive letter in the root of which the `"Pictures`" folder will be created.
Press Enter to skip
`nВведите букву диска, в корне которого будет создана папка `"Изображения`".
Чтобы пропустить, нажмите Enter"
	IF ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$regpictures = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Pictures"
		IF ($regpictures -ne "${drive}:\Pictures")
		{
			IF (-not (Test-Path -Path "${drive}:\Pictures"))
			{
				New-Item -Path "${drive}:\Pictures" -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Pictures -Path "${drive}:\Pictures"
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{0DDD015D-B06C-45D5-8C4C-F59713854639}" -PropertyType ExpandString -Value "${drive}:\Pictures" -Force
			Set-Content -Path "${drive}:\Pictures\desktop.ini" -Value $desktopini["Pictures"] -Encoding Unicode -Force
			(Get-Item -Path "${drive}:\Pictures\desktop.ini").Attributes = "Hidden", "System", "Archive"
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		Read-Host -Prompt "`nThe disk does not exist. Press Enter to skip
`nДиск не существует. Введите букву диска.
Чтобы пропустить, нажмите Enter"
	}
}
Until ($drives -eq $drive)
# Видео
Do
{
	$drive = Read-Host -Prompt "Type the drive letter in the root of which the `"Videos`" folder will be created.
Press Enter to skip
`nВведите букву диска, в корне которого будет создана папка `"Видео`".
Чтобы пропустить, нажмите Enter"
	IF ($drives -eq $drive)
	{
		$drive = $(${drive}.ToUpper())
		$regvideos = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Video"
		IF ($regvideos -ne "${drive}:\Videos")
		{
			IF (-not (Test-Path -Path "${drive}:\Videos"))
			{
				New-Item -Path "${drive}:\Videos" -ItemType Directory -Force
			}
			KnownFolderPath -KnownFolder Videos -Path "${drive}:\Videos"
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" -PropertyType ExpandString -Value "${drive}:\Videos" -Force
			Set-Content -Path "${drive}:\Videos\desktop.ini" -Value $desktopini["Videos"] -Encoding Unicode -Force
			(Get-Item -Path "${drive}:\Videos\desktop.ini").Attributes = "Hidden", "System", "Archive"
		}
	}
	elseif ([string]::IsNullOrEmpty($drive))
	{
		break
	}
	else
	{
		Read-Host -Prompt "`nThe disk does not exist. Press Enter to skip
`nДиск не существует. Введите букву диска.
Чтобы пропустить, нажмите Enter"
	}
}
Until ($drives -eq $drive)
# Удалить "$env:SystemDrive\PerfLogs"
Remove-Item $env:SystemDrive\PerfLogs -Recurse -Force -ErrorAction SilentlyContinue
# Удалить "$env:LOCALAPPDATA\Temp"
Remove-Item $env:LOCALAPPDATA\Temp -Recurse -Force -ErrorAction SilentlyContinue
# Удалить "$env:SYSTEMROOT\Temp"
Restart-Service -ServiceName Spooler -Force
Remove-Item -Path "$env:SystemRoot\Temp" -Recurse -Force -ErrorAction SilentlyContinue
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
# Вывод ошибок
Write-Host "`nErrors" -BackgroundColor Red
($Error | Where-Object -FilterScript {$_ -notmatch "Taskmgr" -and $_ -notmatch "TaskManager"} | ForEach-Object {
	[PSCustomObject] @{
		Line = $_.InvocationInfo.ScriptLineNumber
		Error = $_.Exception.Message
	}
} | Format-Table -AutoSize -Wrap | Out-String).Trim()
