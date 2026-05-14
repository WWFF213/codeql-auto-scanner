# CodeQL 自动化安全检测

基于 DeepSeek 大模型自动生成 CodeQL 查询并执行的安全扫描工具。用户用自然语言描述检测需求，工具调用 LLM 生成对应的 `.ql` 查询，再调用 CodeQL CLI 完成建库、执行、解析告警的完整流水线。

## 特性

- 自然语言 → CodeQL 查询自动生成（基于 DeepSeek）
- 查询执行失败时自动把错误反馈给 LLM 修复重试
- 支持 Java / Python / JavaScript / C-C++ / Go / C# 等语言
- SARIF 结果解析，命令行表格化展示告警
- 内置 5 个测试样例（SQL 注入、命令注入、Use-After-Free、Double Free、Memory Leak）

## 依赖

- Python ≥ 3.9
- [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases)（需在 PATH 中）
- DeepSeek API key

## 安装

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# 安装 Python 依赖
pip install -r requirements.txt

# 复制配置模板并填入 API key
cp config.yaml.example config.yaml
# 编辑 config.yaml，把 api_key 填上
```

## 使用

```bash
# 基础用法
python main.py -r "检测 SQL 注入漏洞" -s ./testcases/java-sqli -l java -y

# 只生成查询不执行（用于预览）
python main.py -r "发现硬编码密码" -s ./testcases/py-secret -l python --dry-run

# 交互模式（不传任何参数）
python main.py
```

### 参数

| 参数 | 含义 |
|---|---|
| `-r` | 检测需求（自然语言） |
| `-s` | 源码目录 |
| `-l` | 目标语言（java/python/javascript/cpp/go/csharp） |
| `-d` | 已有的 CodeQL 数据库路径 |
| `-o` | 输出目录（默认 `./output`） |
| `--dry-run` | 仅生成查询，不执行 |
| `-y` | 跳过执行确认 |
| `-v` | 详细日志 |

## 测试样例

`testcases/` 下有 5 个包含故意漏洞的样例：

| 目录 | 漏洞类型 | 语言 |
|---|---|---|
| `java-sqli/` | SQL 注入 | Java |
| `py-cmdi/` | 命令注入 | Python |
| `c-uaf/` | Use-After-Free | C |
| `c-double-free/` | Double Free | C |
| `c-memory-leak/` | Memory Leak / 资源泄漏 | C |

每个样例都同时包含漏洞代码和安全对照组，可用于验证查询精度。

## 项目结构

```
zidonghua/
├── main.py                  # CLI 入口
├── config.yaml.example      # 配置模板
├── requirements.txt
├── src/
│   ├── deepseek_client.py   # DeepSeek API 客户端
│   ├── codeql_runner.py     # CodeQL CLI 封装
│   └── prompt_builder.py    # 提示词构建
└── testcases/               # 测试样例
```
