for /f "delims=" %%a in (config.ini) do set %%a
powershell.exe -noexit .\Remote-IIS.ps1 ^
-user %user% ^
-password %password% ^
-server %server% ^
-command %command% ^
-action %action% ^
-param %param%