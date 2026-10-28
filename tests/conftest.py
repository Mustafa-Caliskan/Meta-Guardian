"""Test isolation: never touch the developer's real credentials or network.

``backend.config`` loads ``.env`` with ``load_dotenv`` (which does not override
existing variables), so clearing these here means every test runs in mock mode
with no provider configured. Individual tests that need a provider pass explicit
arguments or httpx MockTransports.

This matters: without it a test that builds an "offline" SAM bridge would happily
call the real Modal endpoint through the developer's .env and take 20 s per call.
"""

import os

_NO_NETWORK_ENV = (
    "MODEL_API_KEY",
    "META_API_KEY",
    "BASETEN_API_KEY",
    "FIREWORKS_API_KEY",
    "MODAL_SAM_URL",
    "MODAL_SAM_TOKEN",
    "MG_SAM_TOKEN",
    "MODAL_PROXY_TOKEN",
    "MODAL_PROXY_TOKEN_SECRET",
    "INTERNAL_API_TOKEN",
    "BASELINE_FRAME",
)

for _name in _NO_NETWORK_ENV:
    os.environ[_name] = ""

os.environ["LLM_MODE"] = "mock"
os.environ["TRUST_FORWARDED_FOR"] = "0"
os.environ["PERSIST_INCIDENTS"] = "0"
os.environ["ENABLE_WATCHERS"] = "0"
os.environ["MG_SAM_GPU"] = "cpu"
