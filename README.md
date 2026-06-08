# Amazon Clothing ERP

一个面向亚马逊服装业务的轻量级 ERP 系统，基于 Flask、SQLAlchemy 和 SQLite 构建，覆盖 SKU、库存、采购、销售、FBA 发货、采购计算、货代比价和权限管理等日常流程。

## 功能模块

- 用户、角色与权限管理
- SKU、条码、颜色、尺码和安全库存管理
- 店铺 SKU 与仓库 SKU 映射
- 供应商、客户、仓库资料管理
- 采购订单创建、表格导入、采购计算器和采购订单下载
- 入库、出库、库存流水、历史月份查询和实时库存汇总
- 销售订单、发货确认和库存扣减
- FBA 发货计算器、FBA 在途管理、发货单归档
- 返修/次品处理
- 固定资产管理
- 货代报价导入与比价
- 报表和 Excel 导出
- 登录审计、操作日志和基础安全配置

## 脱敏说明

本仓库只包含应用源码和测试代码，不包含任何运行数据。

以下内容已被排除，不会进入 GitHub：

- `instance/` 运行目录
- SQLite 数据库、WAL/SHM 文件
- 日志文件
- 上传的 Excel/CSV/TSV 文件
- 采购/FBA 计算缓存结果
- 货代报价原始文件
- 本地依赖缓存目录，例如 `.vendor/`、`.vendor_pkgs/`、`.wheels/`
- Python 缓存目录，例如 `__pycache__/`

真实部署时请自行配置环境变量和数据挂载目录。

## 本地运行

建议使用 Python 3.11+。

```bash
pip install -r requirements.txt
python app.py
```

默认访问地址：

```text
http://127.0.0.1:8000
```

## 初始化管理员

首次启动前请设置管理员初始密码：

```bash
set ERP_INIT_ADMIN_PASSWORD=YourStrongPassword123
python app.py
```

Linux/macOS：

```bash
export ERP_INIT_ADMIN_PASSWORD=YourStrongPassword123
python app.py
```

系统不会内置公开默认密码。首次初始化后，请妥善保存账号信息并尽快修改密码。

## 常用环境变量

```text
ERP_SECRET_KEY=replace-this-in-production
ERP_DATABASE_URL=sqlite:///erp.db
ERP_INIT_ADMIN_PASSWORD=YourStrongPassword123
ERP_EMERGENCY_ADMIN_PASSWORD=AnotherStrongPassword123
ERP_HOST=0.0.0.0
ERP_PORT=8000
```

生产环境必须设置稳定且保密的 `ERP_SECRET_KEY`。

## Docker 部署

```bash
docker compose up -d --build
```

默认容器端口为 `8000`。建议将宿主机目录挂载到 `/app/instance`，用于保存数据库、日志和上传文件。

## 群晖 NAS 部署提示

- 端口映射：`8000:8000`
- 挂载数据目录到容器内 `/app/instance`
- 设置 `ERP_SECRET_KEY`
- 设置 `ERP_INIT_ADMIN_PASSWORD`
- 数据库可使用：`sqlite:////app/instance/erp.db`

## 运行测试

```bash
python -m unittest tests.test_regression
```

如果测试或 Excel 导入导出提示缺少依赖，请确认已安装：

```bash
pip install -r requirements.txt
```

## 目录结构

```text
.
├── app.py
├── templates/
├── static/
├── tests/
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## 重要提醒

请不要把生产数据库、客户信息、采购资料、销量表、报价表或任何包含账号密码的配置文件提交到仓库。`.gitignore` 已经默认排除了常见运行数据，但提交前仍建议检查 `git status`。
