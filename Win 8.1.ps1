# Отключить службы диагностического отслеживания
Get-Service -ServiceName DiagTrack | Stop-Service
Get-Service -ServiceName DiagTrack | Set-Service -StartupType Disabled
# Отключить отчеты об ошибках Windows
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Value 1 -Force
# Изменить частоту формирования отзывов на "Никогда"
IF (!(Test-Path -Path HKCU:\Software\Microsoft\Siuf\Rules))
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
"SilentCleanup",
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
IF (!(Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel))
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
IF (!(Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -Value 1 -Force
# Отключить автозапуск с внешних носителей
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -Value 1 -Force
# He дoбaвлять "- яpлык" для coздaвaeмыx яpлыкoв
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name link -Type Binary -Value ([byte[]](00,00,00,00)) -Force
# Всегда отображать все значки в области уведомлений
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -Value 0 -Force
# Установка крупных значков в панели управления
IF (!(Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
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
IF (!(Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Value 1 -Force
# Включить отображение ленты проводника в развернутом виде
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Name MinimizedStateTabletModeOff -Value 0 -Force
# Отключить поиск программ в Microsoft Store
IF (!(Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Value 1 -Force
# Не показывать уведомление "Установлено новое приложение"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -Value 1 -Force
# Отключить OneDrive
IF (!(Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Value 1 -Force
# Всегда ждать сеть при запуске и входе в систему
IF (!(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -Value 1 -Force
# Запрашивать подтверждение при удалении файлов
IF (!(Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ConfirmFileDelete -Value 1 -Force
# Не хранить сведения о зоне происхождения вложенных файлов
IF (!(Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
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
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -Type String -Value Off -Force
# Сохранять скриншот по Win+PrtScr на Рабочем столе
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{b7bede81-df94-4682-a7d8-57a52620b86f}" -Name RelativePath -Type String -Value %USERPROFILE%\Desktop -Force
# Установка качества фона рабочего стола на 100 %
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -Value 100 -Force
# Отключить залипания клавиши Shift после 5 нажатий
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -Type String -Value 506 -Force
# Отключить отображение вкладки "Предыдущие версии" в свойствах файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -Value 1 -Force
# Изменить путь переменной среды для временных файлов
IF (!(Test-Path -Path $env:SystemDrive\Temp))
{
	New-Item -Path $env:SystemDrive\Temp -Type Directory -Force
}
[Environment]::SetEnvironmentVariable("TMP","$env:SystemDrive\Temp","User")
New-ItemProperty -Path HKCU:\Environment -Name TMP -Type ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TEMP","$env:SystemDrive\Temp","User")
New-ItemProperty -Path HKCU:\Environment -Name TEMP -Type ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TMP","$env:SystemDrive\Temp","Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP -Type ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TEMP","$env:SystemDrive\Temp","Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TEMP -Type ExpandString -Value %SystemDrive%\Temp -Force
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
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open -Name MuiVerb -Type String -Value "@photoviewer.dll,-3043" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\command -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\DropTarget -Name Clsid -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\print\command -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\DropTarget -Name Clsid -Type String -Value "{60fd46de-f830-4894-a628-6fa81bc0190d}" -Force
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
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument 'Get-ChildItem -Path "$env:TEMP" -Recurse -Force | Remove-Item -Recurse -Force'
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 61 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
"TaskName"	= "Temp"
"Action"	= $action
"Trigger"	= $trigger
"Settings"	= $settings
}
Register-ScheduledTask @Params -User System -RunLevel Highest -Force
# Включить в Планировщике задач очистки папки %SYSTEMROOT%\SoftwareDistribution\Download
$xml = 'Программы\Прочее\xml\SoftwareDistribution.xml'
function Get-ResolvedPath
{
	param ([Parameter(ValueFromPipeline=1)]$Path)
	(Get-Disk | Where-Object {$_.BusType -eq "USB"} | Get-Partition | Get-Volume | Where-Object {$null -ne $_.DriveLetter}).DriveLetter | ForEach-Object {Join-Path ($_ + ":") $Path -Resolve -ErrorAction SilentlyContinue}
}
$xml | Get-ResolvedPath | Get-Item | Get-Content -Raw | Register-ScheduledTask -TaskName "SoftwareDistribution" -Force
# Включить в Планировщике задач очистки папки %SYSTEMROOT%\LiveKernelReports
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument @"
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
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument @"
`$dir = "$env:SystemRoot\Logs\CBS"
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
	# Cтационарный ПК
	powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
}
Else
{
	# Ноутбук
	powercfg /s 381b4222-f694-41f0-9685-ff5bb260df2e
}
# Использовать последнюю установленную версию .NET Framework для всех приложений
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Value 1 -Force
# Включить Num Lock при загрузке
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -Type String -Value 2147483650 -Force
# Добавить в исключение Windows Defender папку
$file = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1"
cmd.exe /c "takeown /F %WINDIR%\system32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1"
cmd.exe /c "icacls %WINDIR%\system32\WindowsPowerShell\v1.0\Modules\Defender\Defender.psd1 /grant:r Администраторы:F"
(Get-Content $file) | ForEach-Object {
	$_.replace("'MSFT_MpSignature.cdxml',", "'MSFT_MpSignature.cdxml')").
	replace("'MSFT_MpWDOScan.cdxml')", "").
	replace("'Remove-MpThreat',", "'Remove-MpThreat')").
	replace("'Start-MpWDOScan')", "")
} | Out-File $file
$drives = Get-Disk | Where-Object {$_.IsBoot -eq $false}
IF ($drives)
{
	$drives = ($drives | Get-Partition | Get-Volume | Where-Object {$null -ne $_.DriveLetter}).DriveLetter | ForEach-Object {$_ + ':'}
	Foreach ($drive In $drives)
	{
		Add-MpPreference -ExclusionPath $drive\Программы\Прочее -Force
	}
}
# Отключить справку по F1
IF (!(Test-Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
{
	New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type String -Value "" -Force
# Раскрыть окно Диспетчера задач
$taskmgr = Get-Process -Name Taskmgr -ErrorAction SilentlyContinue
IF ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
Do
{
	Start-Sleep -Milliseconds 100
	$preferences = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -ErrorAction SilentlyContinue
}
Until ($preferences)
Stop-Process $taskmgr
$preferences.Preferences[28] = 0
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -Type Binary -Value $preferences.Preferences -Force
# Запретить отключение Ethernet-адаптера для экономии энергии
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
{
	$adapter = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement
	$adapter.AllowComputerToTurnOffDevice = "Disabled"
	$adapter | Set-NetAdapterPowerManagement
}
# Переопределить пользовательский метод ввода на английский язык на экране входа
IF (!(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name BlockUserInputMethodsForSignIn -Value 1 -Force
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 1 -Type String -Value 00000409 -Force
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 2 -Type String -Value 00000419 -Force
# Открепить значок Магазина на панели задач
IF (!(Test-Path -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoPinningStoreToTaskbar -Value 1 -Force
# Открепить от панели задач Microsoft Store
$getstring = @'
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
'@
$getstring = Add-Type $getstring -PassThru -Name GetStr -Using System.Text
$unpinFromStart = $getstring[0]::GetString(5387)
(New-Object -Com Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items() | ForEach-Object { $_.Verbs() | Where-Object {$_.Name -eq $unpinFromStart} | ForEach-Object {$_.DoIt()}}
# Добавить пункт "Извлечь" для MSI в контекстное меню
IF (!(Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Извлечь\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Извлечь\Command -Force
}
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Извлечь\Command -Name "(Default)" -Type String -Value 'msiexec.exe /a "%1" /qb TARGETDIR="%1 extracted"' -Force
# Удалить принтеры
Remove-Printer -Name Fax, "Microsoft XPS Document Writer" -ErrorAction SilentlyContinue
# Добавить "Запуск от имени друго пользователя" в контекстное меню для exe-файлов
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name "(Default)" -Type String -Value "@shell32.dll,-50944" -Force
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name SuppressionPolicyEx -Type String -Value "{F211AA05-D4DF-4370-A2A0-9F19C09756A7}" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser\command -Name DelegateExecute -Type String -Value "{ea72d00e-4960-42fa-ba92-7792a7944c1d}" -Force
# Включить длинные пути Win32
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1 -Force
# Отключить удаление кэша миниатюр
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -Value 0 -Force
# Удалить пункт "Отправить" из контекстного меню
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(Default)" -Type String -Value "" -Force
# Удалить пункт "Включить Bitlocker" из контекстного меню
IF (Get-WindowsEdition -Online | Where-Object {$_.Edition -eq "Professional" -or $_.Edition -eq "Enterprise"})
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
		New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\$key -Name ProgrammaticAccessOnly -Type String -Value "" -Force
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
		[ValidateSet('Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos')]
		[string]$KnownFolder,

		[Parameter(Mandatory = $true)]
		[string]$Path
	)
	$KnownFolders = @{
		'Desktop'	= @('B4BFCC3A-DB2C-424C-B029-7FE99A87C641');
		'Documents'	= @('FDD39AD0-238F-46AF-ADB4-6C85480369C7', 'f42ee2d3-909f-4907-8871-4c22fc0bf756');
		'Downloads'	= @('374DE290-123F-4565-9164-39C4925E467B', '7d83ee9b-2244-4e70-b1f5-5393042af1e4');
		'Music'		= @('4BD8D571-6D19-48D3-BE97-422220080E43', 'a0c69a99-21c8-4671-8703-7934162fcf1d');
		'Pictures'	= @('33E28130-4E1E-4676-835A-98395C3BC3BB', '0ddd015d-b06c-45d5-8c4c-f59713854639');
		'Videos'	= @('18989B1D-99B5-455B-841C-AB7C74E4DDFC', '35286a68-3c57-41a1-bbb1-0eae73d76c95');
	}
	$Type = ([System.Management.Automation.PSTypeName]'KnownFolders').Type
	$Signature = @'
	[DllImport("shell32.dll")]
	public extern static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);
'@
	$Type = Add-Type -MemberDefinition $Signature -Name 'KnownFolders' -Namespace 'SHSetKnownFolderPath' -PassThru
	# return $Type::SHSetKnownFolderPath([ref]$KnownFolders[$KnownFolder], 0, 0, $Path)
	ForEach ($guid in $KnownFolders[$KnownFolder])
	{
		$Type::SHSetKnownFolderPath([ref]$guid, 0, 0, $Path)
	}
	Attrib +r $Path
}
$getdisk = (Get-Disk | Where-Object {$_.BusType -ne "USB"} | Get-Partition | Get-Volume).DriveLetter
# Рабочий стол
$drive = Read-Host -Prompt "Введите букву диска, в корне которого будет создана папка `"Рабочий стол`". `nЧтобы пропустить, нажмите Enter"
IF ($getdisk -eq $drive)
{
	$drive = $(${drive}.ToUpper())
	$Desktop = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
	IF ($Desktop -ne "${drive}:\Рабочий стол")
	{
		IF (!(Test-Path -Path "${drive}:\Рабочий стол"))
		{
			New-Item -Path "${drive}:\Рабочий стол" -Type Directory -Force
		}
		KnownFolderPath -KnownFolder Desktop -Path "${drive}:\Рабочий стол"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}" -Type ExpandString -Value "${drive}:\Рабочий стол" -Force
	}
}
# Документы
$drive = Read-Host -Prompt "Введите букву диска, в корне которого будет создана папка `"Документы`". `nЧтобы пропустить, нажмите Enter"
IF ($getdisk -eq $drive)
{
	$drive = $(${drive}.ToUpper())
	$Documents = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Personal
	IF ($Documents -ne "${drive}:\Документы")
	{
		IF (!(Test-Path -Path "${drive}:\Документы"))
		{
			New-Item -Path "${drive}:\Документы" -Type Directory -Force
		}
		KnownFolderPath -KnownFolder Documents -Path "${drive}:\Документы"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" -Type ExpandString -Value "${drive}:\Документы" -Force
	}
}
# Загрузки
$drive = Read-Host -Prompt "Введите букву диска, в корне которого будет создана папка `"Загрузки`". `nЧтобы пропустить, нажмите Enter"
IF ($getdisk -eq $drive)
{
	$drive = $(${drive}.ToUpper())
	$Downloads = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
	IF ($Downloads -ne "${drive}:\Загрузки")
	{
		IF (!(Test-Path -Path "${drive}:\Загрузки"))
		{
			New-Item -Path "${drive}:\Загрузки" -Type Directory -Force
		}
		KnownFolderPath -KnownFolder Downloads -Path "${drive}:\Загрузки"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}" -Type ExpandString -Value "${drive}:\Загрузки" -Force
	}
}
# Музыка
$drive = Read-Host -Prompt "Введите букву диска, в корне которого будет создана папка `"Музыка`". `nЧтобы пропустить, нажмите Enter"
IF ($getdisk -eq $drive)
{
	$drive = $(${drive}.ToUpper())
	$Music = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Music"
	IF (Music -ne "${drive}:\Музыка")
	{
		IF (!(Test-Path -Path "${drive}:\Музыка"))
		{
			New-Item -Path "${drive}:\Музыка" -Type Directory -Force
		}
		KnownFolderPath -KnownFolder Music -Path "${drive}:\Музыка"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{A0C69A99-21C8-4671-8703-7934162FCF1D}" -Type ExpandString -Value "${drive}:\Музыка" -Force
	}
}
# Изображения
$drive = Read-Host -Prompt "Введите букву диска, в корне которого будет создана папка `"Изображения`". `nЧтобы пропустить, нажмите Enter"
IF ($getdisk -eq $drive)
{
	$drive = $(${drive}.ToUpper())
	$Pictures = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Pictures"
	IF ($Pictures -ne "${drive}:\Изображения")
	{
		IF (!(Test-Path -Path "${drive}:\Изображения"))
		{
			New-Item -Path "${drive}:\Изображения" -Type Directory -Force
		}
		KnownFolderPath -KnownFolder Pictures -Path "${drive}:\Изображения"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{0DDD015D-B06C-45D5-8C4C-F59713854639}" -Type ExpandString -Value "${drive}:\Изображения" -Force
	}
}
# Видео
$drive = Read-Host -Prompt "Введите букву диска, в корне которого будет создана папка `"Видео`". `nЧтобы пропустить, нажмите Enter"
IF ($getdisk -eq $drive)
{
	$drive = $(${drive}.ToUpper())
	$Videos = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Video"
	IF ($Videos -ne "${drive}:\Видео")
	{
		IF (!(Test-Path -Path "${drive}:\Видео"))
		{
			New-Item -Path "${drive}:\Видео" -Type Directory -Force
		}
		KnownFolderPath -KnownFolder Videos -Path "${drive}:\Видео"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" -Type ExpandString -Value "${drive}:\Видео" -Force
	}
}
# Удалить %SYSTEMDRIVE%\PerfLogs
IF ((Test-Path -Path $env:SystemDrive\PerfLogs))
{
	Remove-Item $env:SystemDrive\PerfLogs -Recurse -Force
}
# Удалить %LOCALAPPDATA%\Temp
IF ((Test-Path -Path $env:LOCALAPPDATA\Temp))
{
	Remove-Item $env:LOCALAPPDATA\Temp -Recurse -Force
}
# Удалить %SYSTEMROOT%\Temp
IF ((Test-Path -Path $env:SystemRoot\Temp))
{
	Restart-Service -ServiceName Spooler -Force
	Remove-Item -Path "$env:SystemRoot\Temp" -Recurse -Force
}
Stop-Process -ProcessName explorer
