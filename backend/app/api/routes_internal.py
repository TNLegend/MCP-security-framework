from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.routes_servers import list_servers_from_db
from app.api.routes_tools import list_tools_from_db
from app.db.database import get_db
from app.schemas.server import MCPServerRead
from app.schemas.tool import MCPToolRead
from app.services.signed_service_request import (
    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
    VerifiedServiceRequest,
    require_internal_service_permission,
)

router = APIRouter(prefix="/internal", tags=["Internal Service APIs"])


@router.get("/inventory/servers", response_model=list[MCPServerRead])
def list_internal_inventory_servers(
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INTERNAL_INVENTORY_SERVERS_READ)
    ),
    db: Session = Depends(get_db),
):
    return list_servers_from_db(db)


@router.get("/inventory/tools", response_model=list[MCPToolRead])
def list_internal_inventory_tools(
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_INTERNAL_INVENTORY_TOOLS_READ)
    ),
    db: Session = Depends(get_db),
):
    return list_tools_from_db(db)
