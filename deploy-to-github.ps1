# wyqY 一键推送到 GitHub
# 使用方法: 在 PowerShell 中运行此脚本
# 前提: 已安装 Git 和 GitHub CLI (gh)

$ErrorActionPreference = "Stop"

$GITHUB_USER = "wyqsgy"
$REPO_NAME = "wyqy"
$REPO_DESC = "AI驱动的框架/中间件漏洞集合自动化验证平台 | AI-powered framework/middleware vulnerability verification platform"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  wyqY GitHub 一键部署脚本" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 检查工具
Write-Host "[1/5] 检查工具..." -ForegroundColor Yellow
try { git --version | Out-Null; Write-Host "  Git OK" -ForegroundColor Green } catch { Write-Host "  请先安装 Git: https://git-scm.com" -ForegroundColor Red; exit 1 }
try { gh --version | Out-Null; Write-Host "  GitHub CLI OK" -ForegroundColor Green } catch { Write-Host "  请先安装 GitHub CLI: winget install GitHub.cli" -ForegroundColor Red; exit 1 }

# 检查 GitHub 登录
Write-Host "[2/5] 检查 GitHub 登录状态..." -ForegroundColor Yellow
$authStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  未登录，正在启动登录..." -ForegroundColor Yellow
    gh auth login --web
}
Write-Host "  GitHub 登录 OK" -ForegroundColor Green

# 创建远程仓库
Write-Host "[3/5] 创建 GitHub 仓库..." -ForegroundColor Yellow
gh repo create "$REPO_NAME" --public --description "$REPO_DESC" --source . --push 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  仓库可能已存在，尝试直接关联..." -ForegroundColor Yellow
    git remote remove origin 2>$null
    git remote add origin "https://github.com/$GITHUB_USER/$REPO_NAME.git"
}

# 推送代码
Write-Host "[4/5] 推送代码到 GitHub..." -ForegroundColor Yellow
git branch -M main
git push -u origin main
Write-Host "  推送成功!" -ForegroundColor Green

# 完成
Write-Host "[5/5] 部署完成!" -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  wyqY 已成功推送到 GitHub!" -ForegroundColor Green
  Write-Host "  仓库地址: https://github.com/$GITHUB_USER/$REPO_NAME" -ForegroundColor Green
Write-Host "  Swagger 文档: 启动后端后访问 http://localhost:8000/docs" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "按任意键打开 GitHub 仓库页面..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Start-Process "https://github.com/$GITHUB_USER/$REPO_NAME"
