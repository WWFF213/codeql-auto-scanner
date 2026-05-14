"""CodeQL CLI 封装：建库、执行查询、解析结果。"""

import subprocess
import json
import os
import shutil


class CodeQLError(Exception):
    """CodeQL 操作异常。"""
    pass


def check_installed() -> bool:
    """检查 codeql CLI 是否在 PATH 中可用。"""
    return shutil.which("codeql") is not None


def get_version() -> str:
    """获取 CodeQL 版本信息。"""
    try:
        result = subprocess.run(
            ["codeql", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        return result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
    except Exception:
        return "unknown"


# 这些语言默认会触发 autobuild（找 maven/gradle/make 等），
# 对于单文件测试样例需要 --build-mode=none 跳过编译。
_BUILD_MODE_NONE_LANGUAGES = {"java", "csharp", "cpp", "c-cpp", "kotlin", "swift"}


def create_database(
    source_path: str,
    db_path: str,
    language: str,
    verbose: bool = False,
    build_mode: str = "none",
) -> str:
    """从源码创建 CodeQL 数据库。

    Args:
        source_path: 待分析的源代码目录
        db_path: 数据库输出路径
        language: 编程语言
        verbose: 是否输出详细信息
        build_mode: 编译型语言的构建模式，默认 "none" 跳过 autobuild

    Returns:
        数据库路径

    Raises:
        CodeQLError: 数据库创建失败
    """
    if not os.path.isdir(source_path):
        raise CodeQLError("源码路径不存在: {}".format(source_path))

    db_path = os.path.abspath(db_path)

    cmd = [
        "codeql", "database", "create",
        db_path,
        "--language", language,
        "--source-root", source_path,
        "--overwrite",
    ]

    if language in _BUILD_MODE_NONE_LANGUAGES and build_mode:
        cmd.extend(["--build-mode", build_mode])

    if verbose:
        cmd.append("--verbose")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            if stderr:
                raise CodeQLError("数据库创建失败:\n{}".format(stderr))
            else:
                raise CodeQLError("数据库创建失败（未知错误）")

        return db_path

    except subprocess.TimeoutExpired:
        raise CodeQLError("数据库创建超时（超过10分钟）")
    except FileNotFoundError:
        raise CodeQLError("未找到 codeql 命令，请确认 CodeQL CLI 已安装且在 PATH 中")


def run_query(query_path: str, db_path: str, output_path: str, verbose: bool = False) -> str:
    """执行 CodeQL 查询，输出 SARIF 结果。

    使用 `codeql database analyze` 以稳定获得 SARIF 格式输出；
    查询文件需带有 @kind problem / @kind path-problem 元数据。

    Args:
        query_path: .ql 查询文件路径
        db_path: CodeQL 数据库路径
        output_path: 结果输出路径（SARIF 文件）
        verbose: 是否输出详细信息

    Returns:
        SARIF 输出文件路径

    Raises:
        CodeQLError: 查询执行失败
    """
    if not os.path.isfile(query_path):
        raise CodeQLError("查询文件不存在: {}".format(query_path))
    if not os.path.isdir(db_path):
        raise CodeQLError("数据库不存在: {}".format(db_path))

    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    cmd = [
        "codeql", "database", "analyze",
        db_path,
        query_path,
        "--format=sarif-latest",
        "--output", output_path,
        "--rerun",
    ]

    if verbose:
        cmd.append("--verbose")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            if stderr:
                raise CodeQLError("查询执行失败:\n{}".format(stderr))
            else:
                raise CodeQLError("查询执行失败（未知错误）")

        return output_path

    except subprocess.TimeoutExpired:
        raise CodeQLError("查询执行超时（超过5分钟）")


def parse_sarif(sarif_path: str) -> list[dict]:
    """解析 SARIF 结果文件，提取告警信息。

    Args:
        sarif_path: SARIF 输出文件路径

    Returns:
        告警列表，每条格式: {file, line, column, message, severity, rule}
    """
    if not os.path.isfile(sarif_path):
        return []

    with open(sarif_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for run in data.get("runs", []):
        rules = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[rule["id"]] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_info = rules.get(rule_id, {})
            message = result.get("message", {}).get("text", "")

            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                region = phys.get("region", {})
                artifact = phys.get("artifactLocation", {}).get("uri", "")

                findings.append({
                    "file": artifact,
                    "line": region.get("startLine", 0),
                    "column": region.get("startColumn", 0),
                    "message": message,
                    "severity": rule_info.get("properties", {}).get("problem.severity", "warning"),
                    "rule": rule_info.get("shortDescription", {}).get("text", rule_id),
                })

    return findings


def list_databases() -> list[str]:
    """列出所有已知的 CodeQL 数据库。"""
    try:
        result = subprocess.run(
            ["codeql", "database", "list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        return result.stdout.strip().split("\n") if result.stdout else []
    except Exception:
        return []
