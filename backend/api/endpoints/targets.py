"""
Target management API endpoints
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel, validator
from loguru import logger

from core.database import get_db_session
from models.scan import Target

router = APIRouter()


# Pydantic models
class TargetCreateRequest(BaseModel):
    name: str
    domain: str
    description: Optional[str] = None
    scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None

    @validator('domain')
    def validate_domain(cls, v):
        # Basic domain validation
        if not v or len(v.strip()) == 0:
            raise ValueError('Domain cannot be empty')
        
        # Remove protocol if present
        v = v.replace('http://', '').replace('https://', '').strip()
        
        # Basic format check
        if '.' not in v:
            raise ValueError('Invalid domain format')
        
        return v.lower()


class TargetUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None
    is_active: Optional[bool] = None


class TargetResponse(BaseModel):
    id: UUID
    name: str
    domain: str
    description: Optional[str]
    scope: Optional[List[str]]
    out_of_scope: Optional[List[str]]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TargetListResponse(BaseModel):
    targets: List[TargetResponse]
    total: int
    page: int
    size: int


@router.post("/", response_model=TargetResponse)
async def create_target(
    target_request: TargetCreateRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new scan target"""
    try:
        # Check if domain already exists
        existing_query = select(Target).where(Target.domain == target_request.domain)
        existing_result = await db.execute(existing_query)
        existing_target = existing_result.scalar_one_or_none()
        
        if existing_target:
            raise HTTPException(status_code=400, detail="Target domain already exists")
        
        # Create new target
        target = Target(
            name=target_request.name,
            domain=target_request.domain,
            description=target_request.description,
            scope=target_request.scope or [],
            out_of_scope=target_request.out_of_scope or []
        )
        
        db.add(target)
        await db.commit()
        await db.refresh(target)
        
        logger.info(f"🎯 Created target: {target.domain}")
        
        return TargetResponse.from_orm(target)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create target: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=TargetListResponse)
async def list_targets(
    page: int = 1,
    size: int = 20,
    active_only: bool = True,
    db: AsyncSession = Depends(get_db_session)
):
    """List all targets with pagination"""
    try:
        offset = (page - 1) * size
        
        # Build query
        query = select(Target)
        if active_only:
            query = query.where(Target.is_active == True)
        
        query = query.offset(offset).limit(size).order_by(Target.created_at.desc())
        
        # Execute query
        result = await db.execute(query)
        targets = result.scalars().all()
        
        # Get total count
        count_query = select(Target)
        if active_only:
            count_query = count_query.where(Target.is_active == True)
        
        total_result = await db.execute(count_query)
        total = len(total_result.scalars().all())
        
        target_responses = [TargetResponse.from_orm(target) for target in targets]
        
        return TargetListResponse(
            targets=target_responses,
            total=total,
            page=page,
            size=size
        )
        
    except Exception as e:
        logger.error(f"Failed to list targets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Get a specific target by ID"""
    try:
        query = select(Target).where(Target.id == target_id)
        result = await db.execute(query)
        target = result.scalar_one_or_none()
        
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        return TargetResponse.from_orm(target)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get target {target_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: UUID,
    target_update: TargetUpdateRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """Update a target"""
    try:
        # Get existing target
        query = select(Target).where(Target.id == target_id)
        result = await db.execute(query)
        target = result.scalar_one_or_none()
        
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Update fields
        update_data = target_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(target, field, value)
        
        await db.commit()
        await db.refresh(target)
        
        logger.info(f"📝 Updated target: {target.domain}")
        
        return TargetResponse.from_orm(target)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update target {target_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{target_id}")
async def delete_target(
    target_id: UUID,
    permanent: bool = False,
    db: AsyncSession = Depends(get_db_session)
):
    """Delete a target.
    - Soft delete by default (sets is_active = False)
    - If permanent=True, delete target and all related scans
    - If target is already inactive and permanent not specified, perform permanent delete automatically
    """
    try:
        # Get existing target
        query = select(Target).where(Target.id == target_id)
        result = await db.execute(query)
        target = result.scalar_one_or_none()
        
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Auto-upgrade to permanent delete if target already inactive
        effective_permanent = permanent or (target.is_active is False)
        
        if effective_permanent:
            # Delete related scans first
            from models.scan import Scan
            await db.execute(delete(Scan).where(Scan.target_id == target_id))
            # Delete target
            await db.execute(delete(Target).where(Target.id == target_id))
            await db.commit()
            logger.info(f"🗑️ Permanently deleted target and related scans: {target.domain}")
            return {"message": "Target and related scans deleted permanently"}
        else:
            # Soft delete by setting is_active to False
            target.is_active = False
            await db.commit()
            logger.info(f"🗑️ Soft-deleted target (inactive): {target.domain}")
            return {"message": "Target deactivated (soft delete)"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete target {target_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{target_id}/scans")
async def get_target_scans(
    target_id: UUID,
    page: int = 1,
    size: int = 10,
    db: AsyncSession = Depends(get_db_session)
):
    """Get all scans for a specific target"""
    try:
        # Verify target exists
        target_query = select(Target).where(Target.id == target_id)
        target_result = await db.execute(target_query)
        target = target_result.scalar_one_or_none()
        
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Import here to avoid circular imports
        from models.scan import Scan
        
        offset = (page - 1) * size
        
        # Get scans for this target
        scans_query = (
            select(Scan)
            .where(Scan.target_id == target_id)
            .offset(offset)
            .limit(size)
            .order_by(Scan.created_at.desc())
        )
        
        scans_result = await db.execute(scans_query)
        scans = scans_result.scalars().all()
        
        # Get total count
        total_query = select(Scan).where(Scan.target_id == target_id)
        total_result = await db.execute(total_query)
        total = len(total_result.scalars().all())
        
        return {
            "target_id": target_id,
            "target_domain": target.domain,
            "scans": [
                {
                    "id": scan.id,
                    "name": scan.name,
                    "status": scan.status,
                    "scan_type": scan.scan_type,
                    "progress_percentage": scan.progress_percentage,
                    "created_at": scan.created_at.isoformat() if scan.created_at else None,
                    "updated_at": scan.updated_at.isoformat() if scan.updated_at else None
                }
                for scan in scans
            ],
            "total": total,
            "page": page,
            "size": size
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scans for target {target_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 