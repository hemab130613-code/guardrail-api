from fastapi import FastAPI
from pydantic import BaseModel
import os
import re
import urllib.parse

app = FastAPI()


WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"

SECRET_FILE = "/home/agent/.pgpass"

WRITE_DIR = "/workspace/output"


class ToolCall(BaseModel):
    tool: str
    command: str = None
    path: str = None
    content: str = None
    method: str = None
    url: str = None


def normalize_path(path):
    if not path:
        return ""

    path = path.replace("~", HOME)

    path = os.path.abspath(path)

    return path


def contains_secret_reference(text):

    if not text:
        return False

    patterns = [
        r"\.pgpass",
        r"/home/agent/\.pgpass",
        r"\$HOME/\.pgpass",
        r"~/.pgpass",
    ]

    for p in patterns:
        if re.search(p, text):
            return True

    return False


def check_bash(command):

    if not command:
        return {
            "decision": "allow",
            "reason": "Command is allowed."
        }

    import re
    import base64
    import os

    cmd = command.lower()


    # Environment expansion simulation
    cmd = cmd.replace("$home", "/home/agent")
    cmd = cmd.replace("${home}", "/home/agent")
    cmd = cmd.replace("~", "/home/agent")


    # Remove shell quoting tricks
    cleaned = (
        cmd
        .replace("'", "")
        .replace('"', "")
        .replace("\\", "")
    )


    # Decode base64 strings appearing in command
    b64_candidates = re.findall(
        r'[a-zA-Z0-9+/=]{8,}',
        cleaned
    )

    for item in b64_candidates:
        try:
            decoded = base64.b64decode(item).decode(
                "utf-8",
                errors="ignore"
            ).lower()

            cleaned += decoded

        except Exception:
            pass


    # Collapse path separators
    cleaned = cleaned.replace("//", "/")


    # Normalize traversal manually
    while "../" in cleaned:
        cleaned = re.sub(
            r'[^/]+/\.\./',
            '',
            cleaned
        )


    # Secret detection AFTER normalization
    forbidden = [
        "/home/agent/.pgpass",
        "home/agent/.pgpass",
        ".pgpass"
    ]


    for f in forbidden:
        if f in cleaned:
            return {
                "decision": "block",
                "reason": "Reading /home/agent/.pgpass is forbidden."
            }


    return {
        "decision": "allow",
        "reason": "Command is allowed."
    }

def check_write(path):

    normalized = normalize_path(path)

    if normalized == WRITE_DIR or normalized.startswith(WRITE_DIR + "/"):
        return {
            "decision": "allow",
            "reason": "Write location is permitted."
        }

    return {
        "decision": "block",
        "reason": "Writes are only allowed inside /workspace/output/."
    }


def check_http(url):

    try:
        parsed = urllib.parse.urlparse(url)

        host = parsed.hostname

        allowed = [
            "huggingface.co",
            "registry.npmjs.org"
        ]

        if host in allowed:
            return {
                "decision": "allow",
                "reason": "Host is on the allowlist."
            }

        return {
            "decision": "block",
            "reason": "Host is not allowed."
        }

    except:
        return {
            "decision": "block",
            "reason": "Invalid URL."
        }



@app.post("/check")
def guardrail(req: ToolCall):

    if req.tool == "bash":
        return check_bash(req.command)

    elif req.tool == "write_file":
        return check_write(req.path)

    elif req.tool == "http_request":
        return check_http(req.url)

    return {
        "decision": "block",
        "reason": "Unknown tool."
    }