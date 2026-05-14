"""Hardcoded credentials test case for CodeQL."""

# 漏洞点：硬编码密码 / API key / token
DATABASE_PASSWORD = "P@ssw0rd!2024"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
JWT_SIGNING_KEY = "supersecret_jwt_key_dont_share"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
API_SECRET = "abc123def456"

# 对照组：占位符 / 空值 / 从环境读取，不应被告警
DB_PASSWORD_PLACEHOLDER = "<changeme>"
EMPTY_SECRET = ""
TODO_KEY = "TODO"


def connect():
    return "mysql://admin:{}@db.internal/prod".format(DATABASE_PASSWORD)


def auth_header():
    return {"Authorization": "Bearer " + GITHUB_TOKEN}
