<div align="center">
  <h1>Windows 8.1 Setup Script</h1>

**"Windows 8.1 Setup Script" is a set of tweaks for OS fine-tuning and automating the routine tasks** 🏆
</div>

[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Q5Q51QUJC)

## Core features

- Set up Privacy & Telemetry;
- Turn off diagnostics tracking scheduled tasks;
- Set up UI & Personalization;
- Interactive prompts;
- Change %TEMP% environment variable path to %SystemDrive%\Temp
- Change location of the user folders programmatically (without moving user files) within interactive menu using up/down arrows and Enter key to make a selection
  - "Desktop";
  - "Documents";
  - "Downloads";
  - "Music";
  - "Pictures"
  - "Videos.
- Uninstall UWP apps from all accounts;
- Turn off Windows features;
- Create a Windows cleaning up task in the Task Scheduler;
- Create tasks in the Task Scheduler to clear
  - %SystemRoot%\SoftwareDistribution\Download
  - %TEMP%
- Add exclusion folder from Microsoft Defender Antivirus scanning using dialog menu;
- Add exclusion file from Microsoft Defender Antivirus scanning using dialog menu;
- Refresh desktop icons, environment variables and taskbar without restarting File Explorer;
- Many more File Explorer and context menu "deep" tweaks.

## Usage

To run the script:

- Download [up-to-date version](https://github.com/farag2/Setup-Windows-10/releases);
- Expand the archive;
- Check whether .ps1 is encoded in **UTF-8 with BOM**;
- Run .ps1 file via powershell.exe;
  - Or Start.cmd as Administrator. The script will start immediately.

## FAQ

Read the code you run carefully. Some functions are presented as an example only. You must be aware of the meaning of the functions in the code. **If you're not sure what the script does, do not run it**.
**Strongly recommended to run the script after fresh installation**. Some of functions can be run also on LTSB/LTSC and on older versions of Windows and PowerShell (not recommended to run on the x86 systems).

## Ask a question on

- [Habr](https://habr.com/en/post/465365/)
- [Ru-Board](http://forum.ru-board.com/topic.cgi?forum=62&topic=30617#15)
- [4PDA](https://4pda.ru/forum/index.php?s=&showtopic=523489&view=findpost&p=95909388)
- [My Digital Life](https://forums.mydigitallife.net/threads/powershell-script-setup-windows-10.81675/)
- [Reddit](https://www.reddit.com/r/PowerShell/comments/go2n5v/powershell_script_setup_windows_10/)
