PowerSyncPro Migration Agent — Intune removal package V2

V2 safely checks whether registry objects contain DisplayName before reading it.
This prevents Set-StrictMode failures on uninstall entries without DisplayName.

Package:
IntuneWinAppUtil.exe -c "<source folder>" -s "Uninstall-PSPMA.ps1" -o "<output folder>" -q

Install command:
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "exit 0"

Uninstall command:
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ".\Uninstall-PSPMA.ps1"

Detection:
Use Detect-PSPMA.ps1 as a custom detection script.
Run as 32-bit process on 64-bit clients: No.

Log:
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Uninstall-PowerSyncProMigrationAgent.log
