@echo off
rem Builds the GoTriage Ghidra extension zip and the standalone CLI jar into dist\
setlocal
if "%GHIDRA_INSTALL_DIR%"=="" set GHIDRA_INSTALL_DIR=D:\ghidra_12.2_PUBLIC
if "%JAVA_HOME%"=="" set JAVA_HOME=D:\jdk-25.0.5+8
set GRADLE=gradle
where gradle >nul 2>nul || set GRADLE=D:\gradle-9.5.0\bin\gradle.bat
call "%GRADLE%" --offline -PGHIDRA_INSTALL_DIR="%GHIDRA_INSTALL_DIR%" buildExtension %*
