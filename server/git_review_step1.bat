@echo off
chcp 65001 >nul
cd /d "%~dp0"
set OUT=%USERPROFILE%\Downloads\qg_git_review
if not exist "%OUT%" mkdir "%OUT%"
echo [read-only] git review - no commit, no push
git rev-parse --abbrev-ref HEAD > "%OUT%\branch.txt" 2>&1
git rev-parse HEAD > "%OUT%\head.txt" 2>&1
git fetch origin > "%OUT%\fetch.txt" 2>&1
git rev-parse origin/main > "%OUT%\origin_main.txt" 2>&1
git log --oneline HEAD..origin/main > "%OUT%\incoming_commits.txt" 2>&1
git log --oneline origin/main..HEAD > "%OUT%\outgoing_commits.txt" 2>&1
git -c core.quotepath=false status --porcelain=v1 -uall > "%OUT%\status.txt" 2>&1
git -c core.quotepath=false diff HEAD > "%OUT%\diff_vs_head.txt" 2>&1
git -c core.quotepath=false diff --stat HEAD > "%OUT%\diffstat_vs_head.txt" 2>&1
git -c core.quotepath=false diff --stat HEAD origin/main > "%OUT%\head_vs_origin_main_stat.txt" 2>&1
git -c core.quotepath=false check-ignore -v .env experiments\data\raw\offline_urls.csv > "%OUT%\ignore_check.txt" 2>&1
git remote -v > "%OUT%\remote.txt" 2>&1
echo done > "%OUT%\DONE.txt"
echo Done. Results in %OUT%
