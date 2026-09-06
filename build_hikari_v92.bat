@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set PATH=C:\Qt\6.10.3\msvc2022_64\bin;%PATH%
"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" -C "C:\Users\ren\Desktop\astro-v92\build_hikari"
echo BUILD_RC=%ERRORLEVEL%
