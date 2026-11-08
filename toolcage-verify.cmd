@echo off
setlocal
wsl.exe --cd "%cd%" -d Ubuntu -u root -- toolcage-verify %*
exit /b %ERRORLEVEL%
