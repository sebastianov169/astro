@echo off
REM Lanzador de UtopiaDashboard - copia el exe a un dir limpio y lo ejecuta
REM (el directorio build del proyecto rompe la red de Qt)
set SRC=C:\Users\andre\Downloads\PRIVEITI2025\Utopia-Project\build\UtopiaDashboard.exe
set RUN=%TEMP%\utopia_run
mkdir "%RUN%" 2>nul
copy /y "%SRC%" "%RUN%\UtopiaDashboard.exe" >nul
set PATH=C:\Qt\6.8.3\mingw_64\bin;C:\Qt\Tools\mingw1310_64\bin;%PATH%
cd /d "%RUN%"
start "" "%RUN%\UtopiaDashboard.exe"
