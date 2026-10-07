@echo off
REM 1) Create an EMPTY repository on GitHub (no README, no license), then run this file and paste its URL.
set /p REPO=Repository URL (https://github.com/USER/NAME.git): 
git remote remove origin 2>nul
git remote add origin %REPO%
git branch -M main
git push -u origin main --tags
pause
