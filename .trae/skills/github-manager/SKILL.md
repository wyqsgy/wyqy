---
name: "github-manager"
description: "GitHub仓库管理自动化技能。管理wyqsgy账号下的仓库，支持创建、删除、推送、同步操作。当用户要求管理GitHub仓库、推送代码、创建/删除仓库时调用。"
---

# GitHub 仓库管理 Skill

## 账号信息

- **GitHub 用户名**: `wyqsgy`
- **主仓库**: `wyqsgy/wyqy` (wyqY 项目)
- **Token 权限**: `repo` + `workflow` (完整读写权限)
- **Token 存储位置**: 本地环境变量 `GITHUB_PAT` 或通过用户对话获取

## 认证配置

### 设置 Git Remote (含Token)
```powershell
cd e:\trae_project\glm\vulnark
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
git remote set-url origin https://<TOKEN>@github.com/wyqsgy/wyqy.git
```

### GitHub API 请求头
```
Authorization: token <TOKEN>
```

## 常用操作

### 1. 推送代码到 GitHub
```powershell
cd e:\trae_project\glm\vulnark
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
git remote set-url origin https://<TOKEN>@github.com/wyqsgy/wyqy.git
git add -A
git commit -m "描述性提交信息"
git push origin main
```

### 2. 查看仓库状态
```powershell
git status
git log --oneline -5
git remote -v
```

### 3. 列出所有仓库
```powershell
$headers = @{ Authorization = "token <TOKEN>" }
Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Headers $headers | Select-Object name, html_url, private
```

### 4. 创建新仓库
```powershell
$headers = @{ Authorization = "token <TOKEN>" }
$body = @{ name = "repo-name"; private = $false } | ConvertTo-Json
Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Method POST -Headers $headers -Body $body -ContentType "application/json"
```

### 5. 删除仓库
```powershell
$headers = @{ Authorization = "token <TOKEN>" }
Invoke-RestMethod -Uri "https://api.github.com/repos/wyqsgy/repo-name" -Method DELETE -Headers $headers
```

### 6. 同步远程仓库
```powershell
git remote set-url origin https://<TOKEN>@github.com/wyqsgy/wyqy.git
git fetch origin
git pull origin main
```

### 7. 自动清理无用仓库
```powershell
$headers = @{ Authorization = "token <TOKEN>" }
$repos = Invoke-RestMethod -Uri "https://api.github.com/user/repos?per_page=100" -Headers $headers
$repos | ForEach-Object { Write-Host "$($_.name) - $($_.html_url)" }
```

### 8. 完整的一键推送流程
```powershell
cd e:\trae_project\glm\vulnark
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
git remote set-url origin https://<TOKEN>@github.com/wyqsgy/wyqy.git
git add -A
git status --short
git commit -m "feat: your commit message"
git push origin main
git remote set-url origin https://github.com/wyqsgy/wyqy.git
```

## 注意事项

1. `<TOKEN>` 需要替换为实际的 GitHub Personal Access Token
2. Token 由用户在对话中提供，不要硬编码到文件中
3. 推送完毕后移除 remote URL 中的 token
4. 提交规范: 使用语义化提交 (feat/fix/docs/refactor/chore)
