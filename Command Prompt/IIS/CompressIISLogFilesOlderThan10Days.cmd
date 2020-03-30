REM ========================================================================
REM                 Microsoft Disclaimer
REM ========================================================================
REM This Sample Code is provided for the purpose of illustration only
REM and is not intended to be used in a production environment.  THIS
REM SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
REM WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
REM LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
REM FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
REM right to use and modify the Sample Code and to reproduce and distribute
REM the object code form of the Sample Code, provided that You agree:
REM (i) to not use Our name, logo, or trademarks to market Your software
REM product in which the Sample Code is embedded; (ii) to include a valid
REM copyright notice on Your software product in which the Sample Code is
REM embedded; and (iii) to indemnify, hold harmless, and defend Us and
REM Our suppliers from and against any claims or lawsuits, including
REM attorneys' fees, that arise or result from the use or distribution
REM of the Sample Code.

@ECHO OFF
CLS
SETLOCAL


SET LOG_FILE=%~dpn0.log
SET ERROR_FILE=%~dpn0.err

FOR /F "delims=" %%i IN ('%windir%\system32\inetsrv\appcmd list site /text:id') DO (
FOR /F "delims=" %%j IN ('%windir%\system32\inetsrv\appcmd.exe list site /id:%%i /text:logfile.directory') DO (
ECHO [%DATE% %TIME%] Processing %%j\W3SVC%%i ... >> %LOG_FILE% 2>>%ERROR_FILE%
FORFILES /p %%j\W3SVC%%i /s /m *.* /d -30 /c "cmd /c echo Erasing @path ... && del @path /s" >> %LOG_FILE% 2>>%ERROR_FILE%
)
)

SET LOG_FILE=
SET ERROR_FILE=