@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" -vcvars_ver=14.44 >nul
cl 2>&1 | findstr /C:"Version"
echo VCVER_CHECK_DONE
