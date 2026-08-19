from common.project_environment import load_project_environment

load_project_environment()

from proxy.gateway import create_gateway_app


app = create_gateway_app()
