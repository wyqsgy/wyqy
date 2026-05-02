# wyqY - AI驱动的框架/中间件漏洞集合自动化验证平台

<p align="center">
  <strong>🛡️ 集成化 · 自动化 · AI驱动</strong>
</p>

## 简介

wyqY 是一个专注于**主流框架和中间件漏洞**的自动化验证平台，集成 AI 智能分析能力，可自动发现、验证和报告安全漏洞。

## 支持的漏洞模块

| 组件 | 漏洞类型 | CVE编号 | 风险等级 |
|------|---------|---------|---------|
| **Spring Framework** | Spring4Shell RCE | CVE-2022-22965 | 严重 |
| **Spring Framework** | SpEL 注入 | CVE-2022-22963 | 严重 |
| **Spring Framework** | Actuator 未授权访问 | - | 高危 |
| **Spring Cloud Gateway** | SpEL RCE | CVE-2022-22947 | 严重 |
| **Spring Cloud Function** | 路由表达式RCE | CVE-2022-22963 | 严重 |
| **Apache Shiro** | RememberMe 反序列化 | CVE-2016-4437 | 严重 |
| **Apache Shiro** | 权限绕过 | CVE-2020-1957 | 高危 |
| **Log4j2** | JNDI 注入 (Log4Shell) | CVE-2021-44228 | 严重 |
| **Fastjson** | 反序列化 RCE | CVE-2017-18349 | 严重 |
| **Nacos** | 认证绕过 | CVE-2021-29441 | 高危 |
| **Nacos** | Derby SQL注入 RCE | CVE-2021-29442 | 严重 |
| **Druid** | 监控面板未授权访问 | - | 中危 |
| **Tomcat** | Manager 未授权/弱口令 | - | 高危 |
| **Struts2** | OGNL 注入系列 | CVE-2017-5638 | 严重 |

## 核心特性

- **插件化架构**: 每个漏洞模块独立封装，易于扩展
- **AI误报过滤**: 基于特征工程 + ML模型智能过滤误报
- **自动化报告**: 一键生成专业安全报告（HTML格式）
- **异步扫描**: 多线程并发扫描，支持任务管理
- **现代化前端**: React + TailwindCSS 仪表板

## 快速开始

### 方式一：Docker 一键部署

```bash
docker-compose up -d
```

访问 http://localhost:3080

### 方式二：本地开发

**后端：**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**前端：**
```bash
cd frontend
npm install
npm run dev
```

访问 http://localhost:3000

### API文档

后端启动后访问 http://localhost:8000/docs

## 项目结构

```
wyqy/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI入口
│   │   ├── config.py            # 配置管理
│   │   ├── database.py          # 数据库连接
│   │   ├── api/                 # API路由
│   │   ├── models/              # 数据模型
│   │   ├── scanner/             # 扫描引擎
│   │   │   ├── base.py          # 扫描器基类
│   │   │   ├── loader.py        # 插件化加载
│   │   │   ├── engine.py        # 异步扫描引擎
│   │   │   └── modules/         # 漏洞模块
│   │   └── ai/                  # AI分析模块
│   │       ├── classifier.py    # 误报过滤器
│   │       ├── feature_extractor.py
│   │       └── report_generator.py
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── api/                 # API调用
│       ├── components/          # 组件
│       └── pages/               # 页面
├── docker-compose.yml
└── .github/workflows/ci.yml    # CI/CD
```

## 技术栈

- **后端**: Python, FastAPI, SQLAlchemy, SQLite
- **前端**: React, TailwindCSS, Recharts, Vite
- **AI**: 特征工程 + 规则引擎 + ML分类器
- **部署**: Docker, Nginx, GitHub Actions

## 免责声明

本工具仅用于**合法的安全测试和教育研究**目的。使用者需确保已获得目标系统的授权。任何未经授权的非法使用，责任由使用者自行承担。
