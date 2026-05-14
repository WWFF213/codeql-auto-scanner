#!/usr/bin/env python3
"""CodeQL 自动化检测脚本 — 由 DeepSeek 大模型生成 CodeQL 查询并自动执行。

用法:
  python main.py -r "检测SQL注入漏洞" -s ./my_project -l java
  python main.py -r "发现硬编码密码" -s ./code -l python --dry-run
  python main.py  (交互模式)
"""

import argparse
import os
import sys
import textwrap
from datetime import datetime

# 确保 src 目录在 Python path 中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.markup import escape
from rich import box

from src.deepseek_client import generate_query, fix_query
from src.codeql_runner import (
    check_installed,
    get_version,
    create_database,
    run_query,
    parse_sarif,
    CodeQLError,
)

MAX_FIX_ATTEMPTS = 2

console = Console()


def load_config():
    """加载 YAML 配置文件。"""
    import yaml

    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def save_query(ql_code: str, output_dir: str) -> str:
    """保存生成的 .ql 文件到 output 目录，返回文件路径。"""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = "query_{}.ql".format(timestamp)
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(ql_code)
    return filepath


def display_query(ql_code: str):
    """用语法高亮展示生成的 CodeQL 查询。"""
    console.print(Panel.fit(
        Syntax(ql_code, "ql", theme="monokai", line_numbers=True),
        title="[bold green]生成的 CodeQL 查询[/bold green]",
        border_style="green",
    ))


def display_results(findings: list[dict]):
    """以表格形式展示检查结果。"""
    if not findings:
        console.print("[green]✓ 未发现安全问题[/green]")
        return

    table = Table(title="检测结果", box=box.SIMPLE_HEAVY)
    table.add_column("#", style="dim", width=4)
    table.add_column("文件", style="cyan", max_width=50)
    table.add_column("行号", justify="right")
    table.add_column("问题描述", style="yellow", max_width=60)
    table.add_column("严重度", justify="center")

    severity_styles = {
        "error": "[bold red]HIGH[/bold red]",
        "warning": "[yellow]MEDIUM[/yellow]",
        "note": "[dim]LOW[/dim]",
    }

    for i, f in enumerate(findings, 1):
        sev = severity_styles.get(f.get("severity", ""), f.get("severity", "?"))
        msg = textwrap.shorten(f.get("message", ""), width=60, placeholder="...")
        table.add_row(
            str(i),
            f.get("file", "?"),
            str(f.get("line", "?")),
            msg,
            sev,
        )

    console.print()
    console.print(table)
    console.print("[bold]共发现 {} 个潜在问题[/bold]".format(len(findings)))


def run_pipeline(args):
    """执行完整的检测流水线。"""
    config = load_config()

    # Step 1: 检查 CodeQL CLI
    console.print("[bold]Step 1/4:[/bold] 检查 CodeQL CLI...", end=" ")
    if not check_installed():
        console.print("[red]✗ 未找到 codeql 命令[/red]")
        console.print(
            "[yellow]请安装 CodeQL CLI: https://github.com/github/codeql-cli-binaries[/yellow]"
        )
        sys.exit(1)
    version = get_version()
    console.print("[green]✓[/green] ({})".format(version))

    # Step 2: 调用 DeepSeek 生成查询
    console.print("[bold]Step 2/4:[/bold] 调用 DeepSeek 生成 CodeQL 查询...")
    try:
        ql_code = generate_query(args.requirement, args.language, verbose=args.verbose)
    except Exception as e:
        console.print("[red]生成失败: {}[/red]".format(escape(str(e))))
        sys.exit(1)

    display_query(ql_code)

    # Dry-run 模式：只预览不执行
    if args.dry_run:
        console.print("[yellow]--dry-run 模式，查询未执行。[/yellow]")
        output_dir = args.output or config["output"]["dir"]
        ql_path = save_query(ql_code, output_dir)
        console.print("[dim]查询已保存到: {}[/dim]".format(ql_path))
        return

    # 询问用户是否继续执行
    if args.yes:
        confirmed = True
    else:
        confirmed = console.input("\n[bold yellow]是否执行该查询? [y/N]:[/bold yellow] ").strip().lower() in ("y", "yes")

    if not confirmed:
        console.print("[dim]已取消执行。[/dim]")
        return

    # Step 3: 准备数据库
    output_dir = args.output or config["output"]["dir"]
    db_path = args.database or config["codeql"]["default_db_path"]

    if not args.database and not os.path.isdir(db_path):
        console.print("[bold]Step 3/4:[/bold] 创建 CodeQL 数据库...")
        source_path = args.source or config["codeql"]["default_source_path"]
        if not source_path:
            console.print("[red]请指定源码路径 (--source)[/red]")
            sys.exit(1)
        try:
            db_path = create_database(source_path, db_path, args.language, verbose=args.verbose)
            console.print("[green]✓ 数据库已创建: {}[/green]".format(escape(db_path)))
        except CodeQLError as e:
            console.print("[red]{}[/red]".format(escape(str(e))))
            sys.exit(1)
    else:
        if not os.path.isdir(db_path):
            console.print("[red]数据库不存在: {}[/red]".format(escape(db_path)))
            sys.exit(1)
        console.print("[bold]Step 3/4:[/bold] [green]✓ 使用已有数据库: {}[/green]".format(escape(db_path)))

    # Step 4: 保存查询并执行（失败时让 DeepSeek 修复后重试）
    console.print("[bold]Step 4/4:[/bold] 执行 CodeQL 查询...")
    ql_path = save_query(ql_code, output_dir)
    sarif_path = os.path.join(output_dir, "results_{}.sarif".format(datetime.now().strftime("%Y%m%d_%H%M%S")))

    attempt = 0
    last_error = None
    while True:
        try:
            sarif_path = run_query(ql_path, db_path, sarif_path, verbose=args.verbose)
            console.print("[green]✓ 查询执行完成[/green]")
            break
        except CodeQLError as e:
            last_error = str(e)
            console.print("[red]查询执行失败:[/red]")
            console.print(last_error, markup=False)

            if attempt >= MAX_FIX_ATTEMPTS:
                console.print("[yellow]已达最大修复次数 ({})，停止重试。[/yellow]".format(MAX_FIX_ATTEMPTS))
                console.print("\n[yellow]生成的 .ql 文件已保存: {}[/yellow]".format(escape(ql_path)))
                console.print("[dim]你可以手动修改后运行: codeql database analyze {} {} --format=sarif-latest --output=result.sarif[/dim]".format(escape(db_path), escape(ql_path)))
                sys.exit(1)

            attempt += 1
            console.print("[cyan]→ 第 {}/{} 次：把错误反馈给 DeepSeek 让其修复...[/cyan]".format(attempt, MAX_FIX_ATTEMPTS))
            try:
                ql_code = fix_query(
                    args.requirement, args.language, ql_code, last_error, verbose=args.verbose
                )
            except Exception as fix_err:
                console.print("[red]修复调用失败: {}[/red]".format(escape(str(fix_err))))
                sys.exit(1)

            display_query(ql_code)
            ql_path = save_query(ql_code, output_dir)

    findings = parse_sarif(sarif_path)
    display_results(findings)

    console.print("\n[dim]查询文件: {}[/dim]".format(escape(ql_path)))
    console.print("[dim]结果文件: {}[/dim]".format(escape(sarif_path)))


def main():
    parser = argparse.ArgumentParser(
        description="CodeQL 自动化检测 — DeepSeek 大模型生成查询 + 自动执行",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            示例:
              %(prog)s -r "检测SQL注入漏洞" -s ./my_project -l java
              %(prog)s -r "发现硬编码的密码和密钥" -s ./src -l python --dry-run
              %(prog)s  (进入交互模式)
        """),
    )

    parser.add_argument(
        "-r", "--requirement",
        type=str,
        help="检测需求描述（自然语言）",
    )
    parser.add_argument(
        "-s", "--source",
        type=str,
        help="待分析源码路径（创建数据库时需要）",
    )
    parser.add_argument(
        "-l", "--language",
        type=str,
        default="java",
        choices=["java", "cpp", "c-cpp", "python", "javascript", "go", "csharp"],
        help="目标编程语言 (default: java)",
    )
    parser.add_argument(
        "-d", "--database",
        type=str,
        help="CodeQL 数据库路径（不指定则自动创建）",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="输出目录 (default: ./output)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅生成查询不执行，预览生成的 .ql 文件",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="跳过执行确认，直接运行",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细输出模式",
    )

    args = parser.parse_args()

    # 如果没有提供 requirement，进入交互模式
    if not args.requirement:
        console.print("[bold cyan]=== CodeQL 自动化检测工具 ===[/bold cyan]")
        console.print("由 DeepSeek 大模型生成 CodeQL 查询语句并自动执行\n")

        args.requirement = console.input("[bold]请输入检测需求:[/bold] ").strip()
        if not args.requirement:
            console.print("[red]需求不能为空[/red]")
            sys.exit(1)

        lang_input = console.input("[bold]目标语言 [java]:[/bold] ").strip()
        if lang_input:
            args.language = lang_input

        if not args.source and not args.database:
            src_input = console.input("[bold]源码路径 (可选，已有数据库可跳过):[/bold] ").strip()
            args.source = src_input or None

    run_pipeline(args)


if __name__ == "__main__":
    main()
