"""Manage the IP blocklist (the system's simulated firewall)."""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import BlockedIP
from app.db.session import get_db
from app.schemas import BlockedIPOut, BlockRequest

router = APIRouter(prefix="/api/blocklist", tags=["blocklist"])


@router.get("", response_model=list[BlockedIPOut])
def list_blocked(db: Session = Depends(get_db)) -> list[BlockedIP]:
    return list(db.scalars(select(BlockedIP).order_by(BlockedIP.id.desc())))


@router.post("", response_model=BlockedIPOut, status_code=201)
def block_ip(body: BlockRequest, db: Session = Depends(get_db)) -> BlockedIP:
    if db.scalar(select(BlockedIP).where(BlockedIP.ip == body.ip)):
        raise HTTPException(status_code=409, detail="IP already blocked")
    entry = BlockedIP(ip=body.ip, reason=body.reason)
    db.add(entry)
    db.commit()
    return entry


@router.delete("/{ip}", status_code=204)
def unblock_ip(ip: str, db: Session = Depends(get_db)) -> Response:
    entry = db.scalar(select(BlockedIP).where(BlockedIP.ip == ip))
    if entry is None:
        raise HTTPException(status_code=404, detail="IP not in blocklist")
    db.delete(entry)
    db.commit()
    return Response(status_code=204)
