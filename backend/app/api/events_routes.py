from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from typing import Optional, List
import json
import asyncio
from ..db.database import connect

router = APIRouter(prefix="/api/events", tags=["Tool-Call & Event Monitoring"])

@router.get("")
def list_events(
    limit: int = Query(default=100, ge=1, le=500),
    agent_id: Optional[str] = None,
    decision: Optional[str] = None,
    min_risk: Optional[int] = None
):
    with connect() as db:
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if decision:
            query += " AND decision = ?"
            params.append(decision.upper())
        if min_risk is not None:
            query += " AND risk_score >= ?"
            params.append(min_risk)
            
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        rows = db.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]

@router.get("/stream")
async def stream_live_events():
    """Server-Sent Events (SSE) endpoint providing live streaming telemetry to SOC monitor."""
    async def event_generator():
        last_id = 0
        with connect() as db:
            row = db.execute("SELECT id FROM events ORDER BY id DESC LIMIT 1").fetchone()
            if row:
                last_id = row[0]
                
        while True:
            await asyncio.sleep(2.5)
            with connect() as db:
                new_rows = db.execute(
                    "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT 10", (last_id,)
                ).fetchall()
                if new_rows:
                    for r in new_rows:
                        last_id = r["id"]
                        yield f"data: {json.dumps(dict(r))}\n\n"
                else:
                    # Heartbeat
                    yield ": heartbeat\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
