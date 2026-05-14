"""DeepSeek API 客户端，调用大模型生成 CodeQL 查询语句。"""

import re
import os
from openai import OpenAI


def _load_config() -> dict:
    """从配置文件和环境变量加载 DeepSeek 配置。"""
    import yaml

    config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    api_key = config["deepseek"]["api_key"] or os.environ.get("DEEPSEEK_API_KEY", "")
    return {
        "api_key": api_key,
        "base_url": config["deepseek"]["base_url"],
        "model": config["deepseek"]["model"],
        "max_tokens": config["deepseek"]["max_tokens"],
        "temperature": config["deepseek"]["temperature"],
    }


def extract_ql_code(response_text: str) -> str:
    """从大模型响应中提取 ```ql / ```codeql ... ``` 代码块。"""
    pattern = r"```(?:ql|codeql|CodeQL)\s*\n(.*?)```"
    matches = re.findall(pattern, response_text, re.DOTALL)
    if matches:
        return matches[0].strip()

    # 回退：尝试提取任意 ``` 代码块
    pattern_any = r"```\w*\s*\n(.*?)```"
    matches_any = re.findall(pattern_any, response_text, re.DOTALL)
    if matches_any:
        return matches_any[0].strip()

    # 如果都没有，返回原始文本（可能模型直接输出了纯代码）
    return response_text.strip()


def _call_deepseek(messages: list, config: dict, verbose: bool = False) -> str:
    """内部统一的 DeepSeek 调用封装，返回提取后的 .ql 代码。"""
    client = OpenAI(api_key=config["api_key"], base_url=config["base_url"])

    if verbose:
        from rich.console import Console
        console = Console()
        console.print("[dim]正在调用 DeepSeek API ({})...[/dim]".format(config["model"]))

    response = client.chat.completions.create(
        model=config["model"],
        messages=messages,
        max_tokens=config["max_tokens"],
        temperature=config["temperature"],
    )
    raw_text = response.choices[0].message.content or ""

    if verbose:
        from rich.console import Console
        console = Console()
        console.print("[dim]API 响应长度: {} 字符[/dim]".format(len(raw_text)))

    ql_code = extract_ql_code(raw_text)
    if not ql_code:
        raise RuntimeError("无法从 API 响应中提取 CodeQL 查询语句")
    return ql_code


def generate_query(requirement: str, language: str = "java", verbose: bool = False) -> str:
    """调用 DeepSeek API 生成 CodeQL 查询语句。"""
    config = _load_config()
    if not config["api_key"]:
        raise ValueError(
            "DeepSeek API key 未配置。请在 config.yaml 中设置或设置环境变量 DEEPSEEK_API_KEY"
        )

    from .prompt_builder import build_messages
    messages = build_messages(requirement, language)

    try:
        return _call_deepseek(messages, config, verbose=verbose)
    except Exception as e:
        raise RuntimeError("DeepSeek API 调用失败: {}".format(e)) from e


def fix_query(
    requirement: str,
    language: str,
    previous_query: str,
    error: str,
    verbose: bool = False,
) -> str:
    """把失败的查询及错误信息喂回 DeepSeek，让其生成修复版。"""
    config = _load_config()
    if not config["api_key"]:
        raise ValueError(
            "DeepSeek API key 未配置。请在 config.yaml 中设置或设置环境变量 DEEPSEEK_API_KEY"
        )

    from .prompt_builder import build_fix_messages
    messages = build_fix_messages(requirement, language, previous_query, error)

    try:
        return _call_deepseek(messages, config, verbose=verbose)
    except Exception as e:
        raise RuntimeError("DeepSeek 修复调用失败: {}".format(e)) from e
