@echo off
echo Starting AI-Based Cybersecurity Assistant...
call "%~dp0venv\Scripts\activate.bat"
if %errorlevel% neq 0 (
    echo Error: Failed to activate virtual environment. Make sure venv is configured.
    pause
    exit /b %errorlevel%
)
python "%~dp0app.py"
pause
