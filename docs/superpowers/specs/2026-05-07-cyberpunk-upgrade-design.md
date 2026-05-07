# 赛博朋克升级设计文档

**日期**: 2026-05-07
**版本**: 2.0.0
**状态**: 已完成

## 概述

本次升级将 Superpowers Security Scanner 从 React JSX 迁移到 TypeScript，并引入了完整的赛博朋克视觉风格。

## 技术栈升级

### 前端
- React 18.2 + TypeScript 5.x
- Vite 5.x (替代 Create React App)
- @tanstack/react-query 5.x
- Tailwind CSS 3.x
- React Router 6.x

### 后端
- Python 3.13
- FastAPI 0.115
- SQLAlchemy 2.0 (async)
- Pydantic 2.x

## 视觉设计

### 主题系统
- Matrix (默认)
- Amber
- Cyberpunk
- Nord
- Dracula
- Ocean
- Midnight
- Retro
- Solarized
- Monokai

### CSS 变量
所有颜色、间距、动画都通过 CSS 变量控制，支持主题切换。

### 动画系统
- GPU 加速的过渡动画
- 脉冲点指示器
- 骨架屏加载
- 页面过渡效果

## 文件结构

```
frontend/
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── index.css
│   ├── api/index.ts
│   ├── lib/queryClient.ts
│   ├── types/
│   │   ├── index.ts
│   │   ├── task.ts
│   │   ├── vulnerability.ts
│   │   ├── scan.ts
│   │   ├── report.ts
│   │   └── api.ts
│   ├── hooks/
│   │   ├── useTasks.ts
│   │   ├── useVulnerabilities.ts
│   │   └── useScan.ts
│   ├── components/
│   │   ├── ui/
│   │   │   ├── NeonCard.tsx
│   │   │   ├── NeonButton.tsx
│   │   │   ├── TerminalOutput.tsx
│   │   │   ├── StatCard.tsx
│   │   │   ├── RiskBadge.tsx
│   │   │   ├── ScanProgress.tsx
│   │   │   └── GlitchTitle.tsx
│   │   ├── Layout.tsx
│   │   ├── ThemeSwitcher.tsx
│   │   ├── LoadingFallback.tsx
│   │   ├── ErrorBoundary.tsx
│   │   ├── Animations.tsx
│   │   ├── VirtualList.tsx
│   │   └── Form.tsx
│   ├── contexts/
│   │   ├── ThemeContext.tsx
│   │   ├── ToastContext.tsx
│   │   └── I18nContext.tsx
│   └── pages/
│       ├── Dashboard.tsx
│       ├── Tasks.tsx
│       ├── NewTask.tsx
│       ├── TaskDetail.tsx
│       ├── Vulnerabilities.tsx
│       ├── Reports.tsx
│       ├── Recon.tsx
│       ├── Attack.tsx
│       ├── POCManagement.tsx
│       ├── PacketVerifier.tsx
│       ├── Templates.tsx
│       └── Settings.tsx
```

## 迁移清单

- [x] TypeScript 配置文件
- [x] Vite 配置
- [x] ESLint 配置
- [x] Prettier 配置
- [x] Vitest 配置
- [x] 类型定义文件
- [x] API 客户端
- [x] React Query hooks
- [x] UI 组件库
- [x] Context providers
- [x] 页面组件
- [x] 赛博朋克 CSS 主题

## 验证命令

```bash
find /workspace/frontend/src -name "*.tsx" | wc -l  # 应 > 25
find /workspace/frontend/src -name "*.jsx" | wc -l    # 应接近 0
ls /workspace/frontend/src/types/                     # 应有 6 个文件
ls /workspace/frontend/src/components/ui/            # 应有 7 个组件
wc -l /workspace/frontend/src/index.css              # 应 > 400
```
