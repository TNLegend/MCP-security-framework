from common.project_environment import load_project_environment

load_project_environment()

from proxy.gateway import create_gateway_app
from proxy.trusted_adapter_packages import load_trusted_adapters_from_environment

load_trusted_adapters_from_environment()

app = create_gateway_app()

# UX-01: freeze the Gateway's loaded build identity at process start.
from common.build_identity import get_build_identity  # noqa: E402

get_build_identity("gateway")
