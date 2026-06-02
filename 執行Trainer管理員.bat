@echo off
:: 自動以管理員身份執行 wartales_trainer.py
:: 把這個 .bat 放在跟 wartales_trainer.py 同一個資料夾

cd /d "%~dp0"

:: 檢查是否已經是管理員
net session >nul 2>&1
if %errorLevel% == 0 (
    echo 已是管理員，直接執行...
    python wartales_trainer.py
) else (
    echo 請求管理員權限...
    powershell -Command "Start-Process python -ArgumentList 'wartales_trainer.py' -WorkingDirectory '%~dp0' -Verb RunAs"
)
