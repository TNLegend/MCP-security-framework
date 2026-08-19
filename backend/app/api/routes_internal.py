from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.routes_servers import list_servers_from_db
from app.api.routes_tools import list_tools_from_db
from app.db.database import get_db
from app.schemas.server import MCPServerInternalRead
from app.schemas.tool import MCPToolRead
from app.services.signed_service_request import (
    PERMISSION_EMERGENCY_DENY_CHECK,
    PERMISSION_INTERNAL_INVENTORY_SERVERS_READ,
    PERMISSION_INTERNAL_INVENTORY_TOOLS_READ,
    VerifiedServiceRequest,
    require_internal_service_permission,
)
from app.services.emergency_deny import check_emergency_deny

router = APIRouter(prefix="/internal", tags=["Internal Service APIs"])


class EmergencyDenyCheckRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    framework_session_id: str = Field(min_length=1, max_length=255)
    server_ref: str = Field(min_length=1, max_length=512)
    tool_name: str = Field(min_length=1, max_length=255)

    model_config = ConfigDict(extra="forbid")


@router.get("/inventory/servers", response_model=list[MCPServerInternalRead])
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


@router.post("/emergency-deny/check")
def check_internal_emergency_deny(
    payload: EmergencyDenyCheckRequest,
    _: VerifiedServiceRequest = Depends(
        require_internal_service_permission(PERMISSION_EMERGENCY_DENY_CHECK)
    ),
    db: Session = Depends(get_db),
):
    deny_id = check_emergency_deny(db, **payload.model_dump())
    return {"blocked": deny_id is not None, "deny_id": deny_id}
