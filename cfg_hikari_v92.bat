@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set PATH=C:\Qt\6.10.3\msvc2022_64\bin;%PATH%
"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" -S "C:\Users\ren\Desktop\astro-v92" -B "C:\Users\ren\Desktop\astro-v92\build_hikari" -G Ninja -DCMAKE_MAKE_PROGRAM="C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" -DCMAKE_C_COMPILER="C:/Users/ren/HikariBuild/build/bin/clang-cl.exe" -DCMAKE_CXX_COMPILER="C:/Users/ren/HikariBuild/build/bin/clang-cl.exe" -DCMAKE_PREFIX_PATH="C:/Qt/6.10.3/msvc2022_64" -DCMAKE_BUILD_TYPE=Release -DCMAKE_MT="C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/mt.exe"
echo CFG_RC=%ERRORLEVEL%
