@echo off
setlocal
wsl.exe --cd "%cd%" -d Ubuntu -u root -- toolcage %*
exit /b %ERRORLEVEL%
