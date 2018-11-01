# Службы диагностического отслеживания
Get-Service DiagTrack | Stop-Service
Get-Service DiagTrack | Set-Service -StartupType Disabled
# Отключить отчеты об ошибках Windows
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Value 1 -Force
# Изменение частоты формирования отзывов на "Никогда"
IF (!(Test-Path HKCU:\Software\Microsoft\Siuf\Rules))
{
	New-Item -Path HKCU:\Software\Microsoft\Siuf\Rules -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name PeriodInNanoSeconds -Value 0 -Force
# Отключение задач диагностического отслеживания в Планировщике задач
Unregister-ScheduledTask "Optimize Start Menu*" -Confirm:$false
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
	Get-ScheduledTask $task | Disable-ScheduledTask
}
# Отключение в "Журналах Windows/Безопасность" сообщения "Платформа фильтрации IP-пакетов Windows разрешила подключение"
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
# Удалить пункт "Закрепить на Начальном экране" из контекстного меню
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen -Force -ErrorAction SilentlyContinue
# Удалить пункт "Закрепить на Начальном экране" из контекстного меню для .exe-файлов
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen -Force -ErrorAction SilentlyContinue
# Открывать "Этот компьютер" в Проводнике
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1 -Force
# Отобразить "Этот компьютер" на Рабочем столе
IF (!(Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Force
# Показывать скрытые файлы
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Value 1 -Force
# Показывать расширения файлов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0 -Force
# Отключить гибридный спящий режим
New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\Power -Name HibernateEnabled -Value 0 -Force
# Не отображать экран блокировки
IF (!(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Value 1 -Force
# Запрашивать подтверждение при удалении файлов
IF (!(Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ConfirmFileDelete -Value 1 -Force
# Запускать проводник с развернутой лентой
IF (!(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name ExplorerRibbonStartsMinimized -Value 2 -Force
# Развернуть диалог переноса файлов
IF (!(Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -Value 1 -Force
# Не скрывать конфликт слияния папок
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -Value 0 -Force
# Отключение автозапуска с внешних носителей
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -Value 1 -Force
# Отключение использования режима одобрения администратором для встроенной учетной записи администратора
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0 -Force
# He дoбaвлять "- яpлык" для coздaвaeмыx яpлыкoв
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name link -Type Binary -Value ([byte[]](00,00,00,00)) -Force
# Отключение поиска программ в Microsoft Store
IF (!(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Value 1 -Force
# Не хранить сведения о зоне происхождения вложенных файлов
IF (!(Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Value 1 -Force
# Отключение SmartScreen для приложений и файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -Type String -Value Off -Force
# Отключение SmartScreen в IE
IF (!(Test-Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter"))
{
	New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter" -Force
}
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -Value 0 -Force
# Сохранение скриншотов по Win+PrtScr на Рабочем столе
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{b7bede81-df94-4682-a7d8-57a52620b86f}" -Name RelativePath -Type String -Value $env:USERPROFILE\Desktop -Force
# Отключение залипания клавиши Shift после 5 нажатий
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -Type String -Value 506 -Force
# Отключение отображения вкладки "Предыдущие версии" в свойствах файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -Value 1 -Force
# Отключить флажки для выбора элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -Value 0 -Force
# Изменение пути переменных сред для временных файлов
IF (!(Test-Path $env:SystemDrive\Temp))
{
	New-Item -Path $env:SystemDrive\Temp -Type Directory -Force
}
[Environment]::SetEnvironmentVariable("TMP","$env:SystemDrive\Temp","User")
[Environment]::SetEnvironmentVariable("TEMP","$env:SystemDrive\Temp","User")
[Environment]::SetEnvironmentVariable("TMP","$env:SystemDrive\Temp","Machine")
[Environment]::SetEnvironmentVariable("TEMP","$env:SystemDrive\Temp","Machine")
# Удаление UWP-приложений
Get-AppxPackage -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
# Отключение компонентов
$features = @(
# Отключение службы Факсы и сканирование
'FaxServicesClientPackage',
# Отключение компонентов прежних версий
'LegacyComponents',
# Отключение компонентов работы с мультимедиа
'MediaPlayback',
# Отключение PowerShell 2.0
'MicrosoftWindowsPowerShellV2',
'MicrosoftWindowsPowershellV2Root',
# Отключение службы XPS
'Printing-XPSServices-Features',
# Отключение и удаление поддержки протокола SMB1 на клиенте
# 'SMB1Protocol',
# Отключение службы "Клиент рабочих папок"
'WorkFolders-Client',
# Отключение просмотрщика XPS
'Xps-Foundation-Xps-Viewer')
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
cmd.exe /c 'ftype Paint.Picture=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1'
cmd.exe /c 'ftype jpegfile=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1'
cmd.exe /c 'ftype pngfile=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1'
cmd.exe /c 'ftype TIFImage.Document=%windir%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1'
cmd.exe /c "assoc .bmp=Paint.Picture"
cmd.exe /c "assoc .jpg=jpegfile"
cmd.exe /c "assoc .jpeg=jpegfile"
cmd.exe /c "assoc .png=pngfile"
cmd.exe /c "assoc .tif=TIFImage.Document"
cmd.exe /c "assoc .tiff=TIFImage.Document"
cmd.exe /c "assoc Paint.Picture\DefaultIcon=%SystemRoot%\System32\imageres.dll,-70"
cmd.exe /c "assoc jpegfile\DefaultIcon=%SystemRoot%\System32\imageres.dll,-72"
cmd.exe /c "assoc pngfile\DefaultIcon=%SystemRoot%\System32\imageres.dll,-71"
cmd.exe /c "assoc TIFImage.Document\DefaultIcon=%SystemRoot%\System32\imageres.dll,-122"
# Отключение OneDrive
IF (!(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Value 1 -Force
# Включить автоматическое обновление для других продуктов Microsoft
(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
# Отключение восстановления системы
Disable-ComputerRestore -drive $env:SystemDrive
Get-ScheduledTask -TaskName SR | Disable-ScheduledTask
Get-Service swprv,vss | Set-Service -StartupType Manual
Get-Service swprv,vss | Start-Service -ErrorAction SilentlyContinue
Get-CimInstance -ClassName Win32_shadowcopy | Remove-CimInstance
Get-Service swprv,vss | Stop-Service -ErrorAction SilentlyContinue
Get-Service swprv,vss | Set-Service -StartupType Disabled
# Отключение Windows Script Host
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Value 0 -Force
# Всегда отображать все значки в области уведомлений
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -Value 0 -Force
# Отключить брандмауэр
Set-NetFirewallProfile -Enabled False -ErrorAction SilentlyContinue
# Включение в Планировщике задач запуска очистки обновлений Windows
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
Register-ScheduledTask @Params -RunLevel Highest -Force
# Включение в Планировщике задач очистки временной папки
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
# Включение в Планировщике задач очистки папки %SYSTEMROOT%\SoftwareDistribution\Download
$xml = 'Программы\Прочее\xml\SoftwareDistribution.xml'
filter Get-FirstResolvedPath
{
	(Get-Disk | Where-Object BusType -eq USB | Get-Partition | Get-Volume).DriveLetter | ForEach-Object {$_ + ':\'} | Join-Path -ChildPath $_ -Resolve -ErrorAction SilentlyContinue | Select-Object -First 1
}
$xml | Get-FirstResolvedPath | Get-Item | Get-Content -Raw | Register-ScheduledTask -TaskName "SoftwareDistribution" -Force
<#
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument @"
`$getservice = Get-Service -Name wuauserv
`$getservice.WaitForStatus('Stopped', '01:00:00')
Get-ChildItem -Path $env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
"@
$trigger = New-ScheduledTaskTrigger -Weekly -At 9am -DaysOfWeek Thursday -WeeksInterval 4
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
"TaskName"	= "SoftwareDistribution"
"Action"	= $action
"Trigger"	= $trigger
"Settings"	= $settings
}
Register-ScheduledTask @Params -User System -RunLevel Highest -Force
#>
# Включение в Планировщике задач удаление устаревших обновлений Office
$drives = (Get-Disk | Where-Object BusType -ne USB | Where-Object IsBoot -ne True | Get-Partition | Get-Volume).DriveLetter | ForEach-Object {$_ + ':'} | Join-Path -ChildPath $_ -Resolve -ErrorAction SilentlyContinue
IF ($drives)
{
	IF (!(Test-Path D:\Программы\Прочее))
	{
		New-Item -ItemType Directory D:\Программы\Прочее -Force
	}
	$bat = 'Программы\Прочее\Office_task.bat'
	$xml = 'Программы\Прочее\xml\Office.xml'
	filter Get-FirstResolvedPath
	{
		(Get-Disk | Where-Object BusType -eq USB | Get-Partition | Get-Volume).DriveLetter | ForEach-Object {$_ + ':\'} | Join-Path -ChildPath $_ -Resolve -ErrorAction SilentlyContinue | Select-Object -First 1
	}
	$bat | Get-FirstResolvedPath | Copy-Item -Destination D:\Программы\Прочее -Force
	$xml | Get-FirstResolvedPath | Get-Item | Get-Content -Raw | Register-ScheduledTask -TaskName "Office" -Force
}
<#
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument @"
`$getservice = Get-Service -Name wuauserv
`$getservice.WaitForStatus('Stopped', '01:00:00')
Start-Process -FilePath D:\Программы\Прочее\Office_task.bat
"@
$trigger = New-ScheduledTaskTrigger -Weekly -At 9am -DaysOfWeek Thursday -WeeksInterval 4
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
"TaskName"	= "Office"
"Action"	= $action
"Trigger"	= $trigger
"Settings"	= $settings
}
Register-ScheduledTask @Params -User System -RunLevel Highest -Force
#>
# Включение в Планировщике задач очистки папки %SYSTEMROOT%\LiveKernelReports
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
# Включение в Планировщике задач очистки папки %SYSTEMROOT%\Logs\CBS
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument @"
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
# Включение в Планировщике задач очистки папки %SYSTEMROOT%\Installer\$PatchCache$\Managed
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument 'Get-ChildItem -Path "$env:SystemRoot\Installer\`$PatchCache$\Managed" -Recurse -Force | Remove-Item -Recurse -Force'
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 120 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
"TaskName"	= "PatchCache"
"Action"	= $action
"Trigger"	= $trigger
"Settings"	= $settings
}
Register-ScheduledTask @Params -User System -RunLevel Highest -Force
# Включение в Планировщике задач очистки папки %ProgramData%\Microsoft\Windows\WER
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument @"
`$dir = '$env:ProgramData\Microsoft\Windows\WER\ReportQueue'
`$foldersize = (Get-ChildItem -Path `$dir -Recurse -Force | Measure-Object -Property Length -Sum).Sum/1MB
IF (`$foldersize -GT 10)
{
	Get-ChildItem -Path `$dir -Recurse -Force | Remove-Item -Recurse -Force
}
"@
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 62 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$params = @{
"TaskName"	= "WER"
"Action"	= $action
"Trigger"	= $trigger
"Settings"	= $settings
}
Register-ScheduledTask @Params -User System -RunLevel Highest -Force
# Домашняя страница в IE
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "Start Page" -Type String -Value https://yandex.ru -Force
# Запускать IE с вкладками с последнего сеанса просмотра
IF (!(Test-Path "HKCU:\Software\Microsoft\Internet Explorer\ContinuousBrowsing"))
{
	New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\ContinuousBrowsing" -Force
}
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\ContinuousBrowsing" -Name Enabled -Value 1 -Force
# Установить схему управления питания для стационарного ПК и ноутбука
IF (((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType) -eq 1)
{
	powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
}
Else
{
	powercfg /s 381b4222-f694-41f0-9685-ff5bb260df2e
}
# Использовать последнюю установленную версию .NET Framework для всех приложений
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Value 1 -Force
# Использовать сценарий автоматической настройки прокси в IE
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name AutoConfigURL -Type String -Value https://antizapret.prostovpn.org/proxy.pac -Force
# Включение Num Lock при загрузке
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
$drives = (Get-Disk | Where-Object IsBoot -ne True | Get-Partition | Get-Volume).DriveLetter | ForEach-Object {$_ + ':'}
IF ($drives)
{
	Foreach ($drive In $drives)
	{
		Add-MpPreference -ExclusionPath $drive\Программы\Прочее -Force
	}
}
Add-MpPreference -ExclusionPath $env:SystemRoot\KMS\bin\SppExtComObjPatcher.exe -Force
Add-MpPreference -ExclusionPath $env:SystemRoot\KMS\bin\SppExtComObjPatcher.dll -Force
Add-MpPreference -ExclusionPath $env:SystemRoot\KMS\bin -Force
# Отключение справки по F1
IF (!(Test-Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
{
	New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type String -Value "" -Force
# Раскрыть окно Диспетчера задач
$taskmgr = Get-Process Taskmgr -ErrorAction SilentlyContinue
IF ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
Start-Process -FilePath Taskmgr
Start-Sleep -s 1
$taskmgr = Get-Process Taskmgr -ErrorAction SilentlyContinue
IF ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
Start-Sleep -s 1
$preferences = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -ErrorAction SilentlyContinue
$preferences.Preferences[28] = 0
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -Type Binary -Value $preferences.Preferences -Force
# Запретить отключение Ethernet-адаптера для экономии энергии
Foreach ($NIC in (Get-NetAdapter -Physical))
{
	$PowerSaving = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi | Where-Object {$_.InstanceName -match [Regex]::Escape($NIC.PnPDeviceID)}
	IF ($PowerSaving.Enable)
	{
		$PowerSaving.Enable = $false
		$PowerSaving | Set-CimInstance
	}
}
# Установка крупных значков в панели управления
IF (!(Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -Value 1 -Force
# Всегда ждать сеть при запуске и входе в систему
IF (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -Value 1 -Force
# Не показывать уведомление "Установлено новое приложение"
IF (!(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -Value 1 -Force
# Переопределение пользовательского метода ввода на английский язык на экране входа
IF (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name BlockUserInputMethodsForSignIn -Value 1 -Force
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 1 -Type String -Value 00000409 -Force
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload" -Name 2 -Type String -Value 00000419 -Force
# Не выполнять мастер запуска IE в первый раз
IF (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name DisableFirstRunCustomize -Value 1 -Force
# Не показывать анимацию при первом входе в систему
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -Value 0 -Force
# Снятие ограничения на одновременное открытие более 15 элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -Value 300 -Force
# Открепить значок Магазина на панели задач
IF (!(Test-Path HKCU:\Software\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoPinningStoreToTaskbar -Value 1 -Force
# Удалить пункт "Добавить в библиотеку" из контекстного меню
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\Library Location" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location" -Recurse -Force -ErrorAction SilentlyContinue
# Удалить пункт "Включить Bitlocker" из контекстного меню
$keys = @(
"encrypt-bde",
"encrypt-bde-elev",
"manage-bde",
"resume-bde",
"resume-bde-elev",
"unlock-bde")
Foreach ($key In $keys)
{
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\$key -Name ProgrammaticAccessOnly -Type String -Value "" -Force
}
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
IF (!(Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Извлечь\Command"))
{
	New-Item -Path "Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Извлечь\Command" -Force
}
New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Извлечь\Command" -Name "(Default)" -Type String -Value 'msiexec.exe /a "%1" /qb TARGETDIR="%1 extracted"' -Force
# Не отображать все папки в области навигации
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name NavPaneShowAllFolders -Value 0 -Force
# Удалить пункт "Отправить" из контекстного меню
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(Default)" -Type String -Value "" -Force
# Удаление принтеров
Remove-Printer -Name Fax, "Microsoft XPS Document Writer" -ErrorAction SilentlyContinue
# Добавить "Запуск от имени друго пользователя" в контекстное меню для exe-файлов
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name "(Default)" -Type String -Value "@shell32.dll,-50944" -Force
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name SuppressionPolicyEx -Type String -Value "{F211AA05-D4DF-4370-A2A0-9F19C09756A7}" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser\command -Name DelegateExecute -Type String -Value "{ea72d00e-4960-42fa-ba92-7792a7944c1d}" -Force
# Включение доступа к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -Value 1 -Force
# Включение длинных путей Win32
New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\FileSystem -Name LongPathsEnabled -Value 1 -Force
# Отключить удаление кэша миниатюр
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -Value 0 -Force
# Удалить пункт "Создать контакт" из контекстного меню
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\.contact\ShellNew" -Recurse -Force -ErrorAction SilentlyContinue
# Удалить пункт "Создать архив ZIP" из контекстного меню
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\.zip\ShellNew" -Recurse -Force -ErrorAction SilentlyContinue
Stop-Process -ProcessName explorer