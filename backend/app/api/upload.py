import logging
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any
from app.api.deps import get_db
from app.services.reporter import InvestigationReporter
from app.db.models import Investigation

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/file")
async def upload_eml_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Uploads a .eml file, parses and investigates its contents, stores the report
    in the database, and returns the result.
    """
    if not file.filename.endswith(('.eml', '.txt')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload a .eml or text file."
        )

    try:
        content_bytes = await file.read()
        raw_eml_text = content_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        logger.error(f"Failed to read file content: {e}")
        raise HTTPException(status_code=400, detail="Could not read uploaded file text.")

    reporter = InvestigationReporter()
    try:
        report = await reporter.run_investigation(raw_eml_text, filename=file.filename)
    except Exception as e:
        logger.error(f"Investigation engine crash: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {str(e)}"
        )

    # Save to database
    try:
        db_record = Investigation(
            filename=file.filename,
            sender=report["parsed_email"]["envelope"]["sender"]["email"],
            recipient=",".join([r["email"] for r in report["parsed_email"]["envelope"]["recipients"]]),
            subject=report["parsed_email"]["envelope"]["subject"],
            date_sent=report["parsed_email"]["envelope"]["date"],
            risk_score=report["risk_assessment"]["score"],
            risk_level=report["risk_assessment"]["level"],
            raw_headers=raw_eml_text,
            analysis_summary=report["metadata"]["analyst_notes_markdown"],
            full_report_json=report
        )
        db.add(db_record)
        await db.flush() # populates the generated id
        
        # Include database generated record id in the metadata response
        report["id"] = db_record.id
        db_record.full_report_json = report # update json with db id
        
    except Exception as e:
        logger.error(f"Failed to write investigation record to database: {e}")
        # We proceed even if DB save fails, but log the error
        pass

    return report

@router.post("/text")
async def upload_raw_text(
    payload: Dict[str, str] = Body(...),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Accepts raw EML/header text in request body, executes threat investigation,
    saves the record, and returns the compiled report.
    """
    raw_text = payload.get("raw_text", "").strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="MIME text body cannot be empty.")

    reporter = InvestigationReporter()
    try:
        report = await reporter.run_investigation(raw_text, filename="raw_headers.txt")
    except Exception as e:
        logger.error(f"Investigation engine crash: {e}")
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")

    # Save to DB
    try:
        db_record = Investigation(
            filename="raw_headers.txt",
            sender=report["parsed_email"]["envelope"]["sender"]["email"],
            recipient=",".join([r["email"] for r in report["parsed_email"]["envelope"]["recipients"]]),
            subject=report["parsed_email"]["envelope"]["subject"],
            date_sent=report["parsed_email"]["envelope"]["date"],
            risk_score=report["risk_assessment"]["score"],
            risk_level=report["risk_assessment"]["level"],
            raw_headers=raw_text,
            analysis_summary=report["metadata"]["analyst_notes_markdown"],
            full_report_json=report
        )
        db.add(db_record)
        await db.flush()
        report["id"] = db_record.id
        db_record.full_report_json = report
    except Exception as e:
        logger.error(f"Failed to write investigation record to database: {e}")

    return report
