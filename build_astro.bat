@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo   Astro - Build Release (MSVC 2026)
echo ============================================
echo.

rem Cierra la app si esta corriendo (el exe bloqueado impide el link)
taskkill /IM Astro.exe /F >nul 2>&1
if %errorlevel%==0 (
    echo [OK] Astro.exe cerrado
) else (
    echo [..] Astro.exe no estaba corriendo
)
echo.

set "CMAKE=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE%" (
    echo [ERROR] No se encontro cmake en:
    echo        %CMAKE%
    echo        Ajusta la ruta en este .bat si tu VS esta en otra carpeta.
    echo.
    pause
    exit /b 1
)

echo [..] Compilando Release...
"%CMAKE%" --build build --config Release
if errorlevel 1 (
    echo.
    echo [ERROR] El build fallo - revisa los errores de arriba.
) else (
    echo.
    echo [OK] Build exitoso: build\Release\Astro.exe
    set /p OPEN=Quieres abrir la app? (S/N): 
    if /i "%OPEN%"=="S" (
        start "" "build\Release\Astro.exe"
        echo [OK] App lanzada
    )
)
echo.
pause
