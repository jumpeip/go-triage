@echo off
rem Standalone Go triage (no Ghidra). Usage: go-triage.bat [--json f] [--csv f] [--md f] [--yara f] [--actor-only] <binary>
setlocal
set JAVA=java
if not "%JAVA_HOME%"=="" set JAVA=%JAVA_HOME%\bin\java
"%JAVA%" -Xmx4g -jar "%~dp0..\dist\go-triage-cli.jar" %*
