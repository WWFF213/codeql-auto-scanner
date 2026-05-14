"""Command injection test case for CodeQL."""
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    # 漏洞点：拼接用户输入后传给 os.system
    host = request.args.get("host")             # source
    os.system("ping -c 1 " + host)              # sink
    return "ok"


@app.route("/lookup")
def lookup():
    # 漏洞点：subprocess 用 shell=True 拼接命令
    domain = request.args.get("domain")         # source
    subprocess.call("nslookup " + domain, shell=True)  # sink
    return "ok"


@app.route("/ping_safe")
def ping_safe():
    # 对照组：参数化调用，不应被告警
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], shell=False)
    return "ok"


if __name__ == "__main__":
    app.run()
