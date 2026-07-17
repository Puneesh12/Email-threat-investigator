import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func
from typing import List, Dict, Any, Optional
from app.api.deps import get_db
from app.db.models import Investigation

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("")
async def list_investigations(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (Low, Medium, High, Critical)"),
    sender: Optional[str] = Query(None, description="Filter by sender address"),
    search: Optional[str] = Query(None, description="Search term matching subject or sender"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Retrieves a list of previous email threat investigations.
    """
    stmt = select(Investigation)

    # Apply Filters
    if risk_level:
        stmt = stmt.where(Investigation.risk_level == risk_level)
    if sender:
        stmt = stmt.where(Investigation.sender.contains(sender.lower()))
    if search:
        stmt = stmt.where(
            Investigation.subject.contains(search) | 
            Investigation.sender.contains(search.lower())
        )

    # Order chronologically (newest first)
    stmt = stmt.order_by(Investigation.created_at.desc())

    # Get count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_count_res = await db.execute(count_stmt)
    total_count = total_count_res.scalar() or 0

    # Apply limits
    stmt = stmt.limit(limit).offset(offset)
    
    results = await db.execute(stmt)
    items = results.scalars().all()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "items": [item.to_dict() for item in items]
    }

@router.get("/stats")
async def get_analytics_stats(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns high-level metric statistics for the SOC Dashboard.
    """
    # 1. Total Case Count
    total_stmt = select(func.count(Investigation.id))
    total_res = await db.execute(total_stmt)
    total_cases = total_res.scalar() or 0

    # 2. Risk Level Distributions
    dist_stmt = select(Investigation.risk_level, func.count(Investigation.id)).group_by(Investigation.risk_level)
    dist_res = await db.execute(dist_stmt)
    distributions = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for lvl, count in dist_res.all():
        if lvl in distributions:
            distributions[lvl] = count

    # 3. Average Risk Score
    avg_stmt = select(func.avg(Investigation.risk_score))
    avg_res = await db.execute(avg_stmt)
    avg_score_raw = avg_res.scalar()
    avg_score = round(float(avg_score_raw), 1) if avg_score_raw is not None else 0.0

    # 4. Critical & High Percentage
    high_critical_count = distributions["High"] + distributions["Critical"]
    malicious_ratio = round((high_critical_count / total_cases * 100), 1) if total_cases > 0 else 0.0

    # 5. Timeline Activity (Last 10 entries)
    timeline_stmt = select(Investigation.created_at, Investigation.risk_score).order_by(Investigation.created_at.desc()).limit(10)
    timeline_res = await db.execute(timeline_stmt)
    activity_timeline = [{"date": row[0].isoformat(), "score": row[1]} for row in timeline_res.all()]
    activity_timeline.reverse() # Chronological for plotting

    return {
        "total_cases": total_cases,
        "average_risk_score": avg_score,
        "malicious_ratio_percentage": malicious_ratio,
        "distributions": distributions,
        "activity_timeline": activity_timeline
    }

@router.get("/{investigation_id}")
async def get_investigation_detail(
    investigation_id: str,
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Fetches the detailed investigation report by UUID.
    """
    stmt = select(Investigation).where(Investigation.id == investigation_id)
    result = await db.execute(stmt)
    investigation = result.scalar_one_or_none()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
        
    return investigation.to_dict()

@router.delete("/{investigation_id}")
async def delete_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Deletes an investigation report record.
    """
    stmt = delete(Investigation).where(Investigation.id == investigation_id)
    result = await db.execute(stmt)
    
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
        
    return {"status": "success", "message": f"Deleted investigation: {investigation_id}"}
