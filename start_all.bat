@echo off
echo ============================================
echo   SDFS - Secure Distributed File System
echo ============================================

echo Installing dependencies...
pip install flask flask-cors PyJWT cryptography requests -q

echo Cleaning previous session...
python cleanup.py

echo.
echo Starting Metadata Server :9000 ...
start "Metadata Server" cmd /k "python metadata_server.py"
timeout /t 3 /nobreak >nul

echo Starting Storage Node :9001 ...
start "Storage Node 9001" cmd /k "python storage_node.py 9001"
timeout /t 2 /nobreak >nul

echo Starting Storage Node :9002 ...
start "Storage Node 9002" cmd /k "python storage_node.py 9002"
timeout /t 2 /nobreak >nul

echo Starting Storage Node :9003 ...
start "Storage Node 9003" cmd /k "python storage_node.py 9003"
timeout /t 2 /nobreak >nul

echo Starting Threat Agent :9005 ...
start "Threat Agent" cmd /k "python threat_agent.py"
timeout /t 2 /nobreak >nul

echo Starting AI Agent :8080 ...
start "AI Agent" cmd /k "python ai_agent.py"
timeout /t 2 /nobreak >nul

echo.
echo ============================================
echo   All services started!
echo   Open dashboard.html in your browser
echo.
echo   Credentials:
echo     adeen    / Admin@2024  (admin)
echo     manahil  / User@2024   (user)
echo     client1  / Client@001  (user)
echo     client2  / Client@002  (user)
echo.
echo   Simulate traffic:  python client.py
echo   Simulate attacks:  python attacker.py
echo   Run benchmark:     python performance_test.py
echo   Fresh start:       python cleanup.py
echo ============================================
pause
