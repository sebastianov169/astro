@echo off
setlocal
set QT=C:\Qt\6.8.3\mingw_64
set BIN=%QT%\bin
set LIB=%QT%\lib
set INC=%QT%\include
set SRC=C:\Users\andre\Downloads\PRIVEITI2025\Utopia-Project
set OUT=%SRC%\build\UtopiaDashboard.exe
set TMPB=%TEMP%\utopia_build
mkdir "%TMPB%" 2>nul

set PATH=%BIN%;%QT%\..\Tools\mingw1310_64\bin;%PATH%

"%BIN%\moc.exe" "%SRC%\src\loginbridge.h" -o "%TMPB%\moc_loginbridge.cpp"
if errorlevel 1 exit /b 1
"%BIN%\moc.exe" "%SRC%\src\login.h" -o "%TMPB%\moc_login.cpp"
if errorlevel 1 exit /b 1

python -c "import sys; q='''<RCC><qresource prefix=\"/Utopia\"><file alias=\"qml/Main.qml\">%SRC%/qml/Main.qml</file><file alias=\"assets/potions/catalog-01.png\">%SRC%/assets/potions/catalog-01.png</file><file alias=\"assets/potions/catalog-02.png\">%SRC%/assets/potions/catalog-02.png</file><file alias=\"assets/potions/catalog-03.png\">%SRC%/assets/potions/catalog-03.png</file><file alias=\"assets/potions/catalog-04.png\">%SRC%/assets/potions/catalog-04.png</file><file alias=\"assets/potions/catalog-05.png\">%SRC%/assets/potions/catalog-05.png</file><file alias=\"assets/visuals/rapper-close.png\">%SRC%/assets/visuals/rapper-close.png</file><file alias=\"assets/visuals/rapper-cross.png\">%SRC%/assets/visuals/rapper-cross.png</file><file alias=\"assets/visuals/mixtape.png\">%SRC%/assets/visuals/mixtape.png</file></qresource></RCC>'''.replace('%SRC%', r'%SRC%'); open(r'%TMPB%\utopia.qrc','w').write(q)"
if errorlevel 1 exit /b 1

python "%SRC%\tools\make_utopia_qrc.py" "%SRC%" "%TMPB%\utopia.qrc"
if errorlevel 1 exit /b 1

"%BIN%\rcc.exe" --name utopia_qrc "%TMPB%\utopia.qrc" -o "%TMPB%\qrc_utopia.cpp"
if errorlevel 1 exit /b 1

g++ -O2 -std=gnu++17 -o "%OUT%" "%SRC%\src\main.cpp" "%SRC%\src\loginbridge.cpp" "%SRC%\src\login.cpp" "%SRC%\src\crypto.cpp" "%TMPB%\moc_loginbridge.cpp" "%TMPB%\moc_login.cpp" "%TMPB%\qrc_utopia.cpp" -I"%SRC%" -I"%INC%" -I"%INC%\QtCore" -I"%INC%\QtGui" -I"%INC%\QtQml" -I"%INC%\QtQuick" -I"%INC%\QtQuickControls2" -I"%INC%\QtNetwork" -I"%INC%\QtConcurrent" -L"%LIB%" -lQt6Core -lQt6Gui -lQt6Qml -lQt6Quick -lQt6QuickControls2 -lQt6Network -lQt6Concurrent -lbcrypt -lncrypt -lcrypt32 -ladvapi32 -lws2_32 -lcomdlg32 -luser32 -lshell32 -lole32 -loleaut32 -luuid
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK
