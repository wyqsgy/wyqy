# 赛博朋克升级计划

**日期**: 2026-05-07
**负责人**: Claude Code
**目标版本**: 2.0.0

## 任务目标

将项目从旧的 JSX 架构升级到 TypeScript + Vite + 赛博朋克主题。

## 执行步骤

### Phase 1: 前端配置
1. 创建 TypeScript 配置文件 (tsconfig.json, tsconfig.app.json, tsconfig.node.json)
2. 配置 Vite (vite.config.ts)
3. 设置 ESLint 和 Prettier
4. 配置 Vitest 测试

### Phase 2: 核心文件
1. 创建类型定义 (types/*.ts)
2. 重写 API 客户端 (api/index.ts)
3. 设置 React Query (lib/queryClient.ts)
4. 重写主入口 (main.tsx, App.tsx)

### Phase 3: 组件库
1. UI 组件 (NeonCard, NeonButton, TerminalOutput, StatCard, RiskBadge, ScanProgress, GlitchTitle)
2. 布局组件 (Layout, ThemeSwitcher)
3. 工具组件 (LoadingFallback, ErrorBoundary, Animations, VirtualList, Form)

### Phase 4: Context
1. ThemeContext - 主题管理
2. ToastContext - 通知系统
3. I18nContext - 国际化

### Phase 5: 页面
1. Dashboard
2. Tasks (列表、新建、详情)
3. Vulnerabilities
4. Reports
5. Recon
6. Attack
7. POCManagement
8. PacketVerifier
9. Templates
10. Settings

### Phase 6: 后端
1. 更新 pyproject.toml (Python 3.13, FastAPI 0.115)
2. 更新 requirements.txt
3. 迁移 main.py 到 lifespan 模式
4. 更新 database.py 到 async 版本
5. 添加测试文件

### Phase 7: 清理
1. 删除所有 .jsx 文件
2. 更新 docker-compose.yml
3. 更新 CI/CD 配置

## 预期结果

- 前端完全迁移到 TypeScript
- 所有页面和组件使用赛博朋克主题
- 后端使用最新异步架构
- 测试通过
- Docker 构建成功
