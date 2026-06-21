import os

import requests

DEFAULT_API_BASE_URL = "http://127.0.0.1:8000/api/v1"


def request_decision(context: dict) -> dict:
    api_base_url = os.getenv("MCP_SECURITY_API_BASE_URL", DEFAULT_API_BASE_URL)
    url = f"{api_base_url.rstrip('/')}/runtime/decision"

    response = requests.post(url, json=context, timeout=10)
    response.raise_for_status()
    return response.json()
