@echo off
rem apk-index -- MCP stdio server launcher (Windows)
rem Env: APK_INDEX_PYTHON / ALLOWED_ROOTS / CACHE_DIR / JADX_HOME / BAKSALI_JAR
setlocal
set "ROOT=%~dp0.."
if "%APK_INDEX_PYTHON%"=="" set "APK_INDEX_PYTHON=python"
set "PYTHONPATH=%ROOT%\src;%PYTHONPATH%"
%APK_INDEX_PYTHON% -m apkindex.server %*
endlocal
