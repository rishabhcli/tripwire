"""FastAPI control plane. Runs on a Vultr VM; the sandbox boundary is Docker, never this process."""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from .agent import ReviewRequest, review, validate_request
from .lab import PAYLOADS, MODE_ORDER, run_lab
from .llm import LLMError, VultrLLM
from .samples import SAMPLES
from .sandbox import SandboxPolicy

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Tripwire")

_hits: dict = defaultdict(deque)
_review_slots = threading.Semaphore(int(os.environ.get("TRIPWIRE_MAX_CONCURRENT", "2")))
_lab_lock = threading.Lock()
_jobs: dict = {}
RATE = int(os.environ.get("TRIPWIRE_RATE_PER_HOUR", "20"))


def _limit(request: Request) -> None:
    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0].strip()
    q = _hits[ip]
    now = time.time()
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= RATE:
        raise HTTPException(429, "rate limit: try again later")
    q.append(now)


class ReviewBody(BaseModel):
    title: str = "Untitled change"
    claim: str = ""
    files: dict = {}
    sample: str | None = None


@app.get("/api/health")
def health():
    return {"ok": True, "model": os.environ.get("TRIPWIRE_MODEL", ""), "inference": os.environ.get(
        "VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1"), "samples": list(SAMPLES),
        "payloads": PAYLOADS, "modes": MODE_ORDER}


@app.get("/api/samples")
def samples():
    return SAMPLES


@app.post("/api/review")
def review_endpoint(body: ReviewBody, request: Request):
    _limit(request)
    if body.sample:
        if body.sample not in SAMPLES:
            raise HTTPException(404, "unknown sample")
        s = SAMPLES[body.sample]
        req = ReviewRequest(s["title"], s["files"], s["claim"])
    else:
        req = ReviewRequest(body.title, body.files, body.claim)
    try:
        validate_request(req)
        llm = VultrLLM()
    except (ValueError, LLMError) as e:
        raise HTTPException(400, str(e))

    def stream():
        if not _review_slots.acquire(timeout=30):
            yield f"data: {json.dumps({'type': 'error', 'message': 'busy, try again'})}\n\n"
            return
        try:
            for ev in review(req, llm, SandboxPolicy()):
                yield f"data: {json.dumps(ev)}\n\n"
        except Exception as e:  # report, do not crash the stream
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)[:300]})}\n\n"
        finally:
            _review_slots.release()

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.post("/api/lab/run")
def lab_run(request: Request):
    _limit(request)
    if not _lab_lock.acquire(blocking=False):
        raise HTTPException(409, "a lab run is already in progress")
    job_id = uuid.uuid4().hex[:10]
    job = {"id": job_id, "status": "running", "cells": [], "summary": None, "total": len(PAYLOADS) * len(MODE_ORDER)}
    _jobs[job_id] = job

    def work():
        try:
            out = run_lab(on_cell=lambda c: job["cells"].append(c))
            job["summary"] = out["summary"]
            job["status"] = "done"
        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)[:300]
        finally:
            _lab_lock.release()

    threading.Thread(target=work, daemon=True).start()
    return {"job": job_id}


@app.get("/api/lab/{job_id}")
def lab_status(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(404, "unknown job")
    return _jobs[job_id]


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
