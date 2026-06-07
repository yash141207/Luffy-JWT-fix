"""
FastAPI wrapper for JWT Generator
Deploy this on Render alongside the original jwt_generator.py (unchanged)
"""

import os
import json
import time
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Union

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

# Import original JWT generator - NO CHANGES to original file
from jwt_generator import (
    process_access_token,
    process_uid_pass,
    save_results_to_json,
    stats,
    results_lock,
    SCRIPT_DIR,
)

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("ff-jwt-api")

# ==================== FASTAPI APP ====================
app = FastAPI(
    title="Free Fire JWT Generator API",
    description="Generate JWT tokens from Free Fire access tokens via FastAPI",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS - allow all origins for public API usage
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Thread pool for blocking IO operations
executor = ThreadPoolExecutor(max_workers=10)

# ==================== PYDANTIC MODELS ====================
class SingleTokenRequest(BaseModel):
    access_token: str = Field(..., description="Free Fire access token", min_length=1)

class SingleTokenResponse(BaseModel):
    success: bool
    jwt: Optional[str] = None
    uid: Optional[str] = None
    region: Optional[str] = None
    nickname: Optional[str] = None
    error: Optional[str] = None
    processing_time_ms: Optional[float] = None

class BulkTokenRequest(BaseModel):
    access_tokens: List[str] = Field(..., description="List of access tokens", min_items=1)

class BulkTokenResponse(BaseModel):
    success: bool
    total: int
    successful: int
    failed: int
    results: List[dict]
    processing_time_ms: Optional[float] = None

class UidPassRequest(BaseModel):
    uid: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

class BulkUidPassRequest(BaseModel):
    credentials: List[UidPassRequest] = Field(..., min_items=1)

class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float

# ==================== STARTUP TRACKING ====================
START_TIME = time.time()

# ==================== HELPERS ====================
def run_in_thread(func, *args, **kwargs):
    """Run a blocking function in thread pool and return result"""
    future = executor.submit(func, *args, **kwargs)
    return future.result()

# ==================== ROUTES ====================
@app.get("/", tags=["Health"])
async def root():
    """Root endpoint - API info"""
    return {
        "name": "Free Fire JWT Generator API",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "running",
    }

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=round(time.time() - START_TIME, 2),
    )

@app.post("/generate", response_model=SingleTokenResponse, tags=["JWT"])
async def generate_jwt(request: SingleTokenRequest):
    """
    Generate JWT from a single access token.
    
    - **access_token**: The Free Fire access token string
    """
    start = time.time()
    
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            executor, process_access_token, request.access_token, time.time()
        )
        
        elapsed_ms = round((time.time() - start) * 1000, 2)
        
        return SingleTokenResponse(
            success=result.get("success", False),
            jwt=result.get("jwt"),
            uid=result.get("uid"),
            region=result.get("region"),
            nickname=result.get("nickname"),
            error=result.get("error"),
            processing_time_ms=elapsed_ms,
        )
    except Exception as e:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        return SingleTokenResponse(
            success=False,
            error=f"Internal error: {str(e)}",
            processing_time_ms=elapsed_ms,
        )

@app.post("/generate/bulk", response_model=BulkTokenResponse, tags=["JWT"])
async def generate_jwt_bulk(request: BulkTokenRequest):
    """
    Generate JWTs for multiple access tokens in parallel.
    
    - **access_tokens**: Array of access token strings
    """
    start = time.time()
    
    if len(request.access_tokens) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 tokens per request")
    
    try:
        # Process all tokens in thread pool
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(executor, process_access_token, token, time.time())
            for token in request.access_tokens
        ]
        results = await asyncio.gather(*tasks)
        
        elapsed_ms = round((time.time() - start) * 1000, 2)
        successful = sum(1 for r in results if r.get("success"))
        
        return BulkTokenResponse(
            success=successful > 0,
            total=len(results),
            successful=successful,
            failed=len(results) - successful,
            results=results,
            processing_time_ms=elapsed_ms,
        )
    except Exception as e:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        return BulkTokenResponse(
            success=False,
            total=0,
            successful=0,
            failed=0,
            results=[],
            processing_time_ms=elapsed_ms,
            error=str(e),
        )

@app.post("/generate/uidpass", response_model=SingleTokenResponse, tags=["JWT"])
async def generate_from_uidpass(request: UidPassRequest):
    """
    Generate JWT from UID and password (Garena login).
    
    - **uid**: Garena UID or email
    - **password**: Garena account password
    """
    start = time.time()
    
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            executor, process_uid_pass, request.uid, request.password, time.time()
        )
        
        elapsed_ms = round((time.time() - start) * 1000, 2)
        
        return SingleTokenResponse(
            success=result.get("success", False),
            jwt=result.get("jwt"),
            uid=result.get("uid"),
            region=result.get("region"),
            nickname=result.get("nickname"),
            error=result.get("error"),
            processing_time_ms=elapsed_ms,
        )
    except Exception as e:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        return SingleTokenResponse(
            success=False,
            error=f"Internal error: {str(e)}",
            processing_time_ms=elapsed_ms,
        )

@app.post("/generate/uidpass/bulk", response_model=BulkTokenResponse, tags=["JWT"])
async def generate_from_uidpass_bulk(request: BulkUidPassRequest):
    """
    Generate JWTs from multiple UID:PASS combinations.
    
    - **credentials**: Array of {uid, password} objects
    """
    start = time.time()
    
    if len(request.credentials) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 credentials per request")
    
    try:
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(executor, process_uid_pass, cred.uid, cred.password, time.time())
            for cred in request.credentials
        ]
        results = await asyncio.gather(*tasks)
        
        elapsed_ms = round((time.time() - start) * 1000, 2)
        successful = sum(1 for r in results if r.get("success"))
        
        return BulkTokenResponse(
            success=successful > 0,
            total=len(results),
            successful=successful,
            failed=len(results) - successful,
            results=results,
            processing_time_ms=elapsed_ms,
        )
    except Exception as e:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        return BulkTokenResponse(
            success=False,
            total=0,
            successful=0,
            failed=0,
            results=[],
            processing_time_ms=elapsed_ms,
            error=str(e),
        )

@app.post("/upload/tokens", response_model=BulkTokenResponse, tags=["Upload"])
async def upload_tokens_file(file: UploadFile = File(...)):
    """
    Upload a JSON file containing access tokens.
    Supports both array of strings and array of objects with token fields.
    """
    start = time.time()
    
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only JSON files are supported")
    
    try:
        content = await file.read()
        data = json.loads(content)
        
        tokens = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    token = item.get("token") or item.get("access_token") or item.get("ACCESS TOKEN")
                    if token:
                        tokens.append(token)
                elif isinstance(item, str):
                    tokens.append(item)
        elif isinstance(data, dict):
            token = data.get("token") or data.get("access_token") or data.get("ACCESS TOKEN")
            if token:
                tokens.append(token)
        
        if not tokens:
            raise HTTPException(status_code=400, detail="No valid tokens found in file")
        
        if len(tokens) > 100:
            tokens = tokens[:100]
        
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(executor, process_access_token, token, time.time())
            for token in tokens
        ]
        results = await asyncio.gather(*tasks)
        
        elapsed_ms = round((time.time() - start) * 1000, 2)
        successful = sum(1 for r in results if r.get("success"))
        
        return BulkTokenResponse(
            success=successful > 0,
            total=len(results),
            successful=successful,
            failed=len(results) - successful,
            results=results,
            processing_time_ms=elapsed_ms,
        )
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file format")
    except Exception as e:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        return BulkTokenResponse(
            success=False,
            total=0,
            successful=0,
            failed=0,
            results=[],
            processing_time_ms=elapsed_ms,
            error=str(e),
        )

@app.post("/upload/credentials", response_model=BulkTokenResponse, tags=["Upload"])
async def upload_credentials_file(file: UploadFile = File(...)):
    """
    Upload a TXT file with UID:PASS pairs (one per line).
    Format: UID:PASSWORD
    """
    start = time.time()
    
    if not file.filename.endswith(".txt"):
        raise HTTPException(status_code=400, detail="Only TXT files are supported")
    
    try:
        content = await file.read()
        lines = content.decode().strip().split("\n")
        
        credentials = []
        for line in lines:
            line = line.strip()
            if line and ":" in line:
                uid, password = line.split(":", 1)
                credentials.append((uid.strip(), password.strip()))
        
        if not credentials:
            raise HTTPException(status_code=400, detail="No valid UID:PASS pairs found")
        
        if len(credentials) > 50:
            credentials = credentials[:50]
        
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(executor, process_uid_pass, uid, pwd, time.time())
            for uid, pwd in credentials
        ]
        results = await asyncio.gather(*tasks)
        
        elapsed_ms = round((time.time() - start) * 1000, 2)
        successful = sum(1 for r in results if r.get("success"))
        
        return BulkTokenResponse(
            success=successful > 0,
            total=len(results),
            successful=successful,
            failed=len(results) - successful,
            results=results,
            processing_time_ms=elapsed_ms,
        )
    except Exception as e:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        return BulkTokenResponse(
            success=False,
            total=0,
            successful=0,
            failed=0,
            results=[],
            processing_time_ms=elapsed_ms,
            error=str(e),
        )

@app.get("/stats", tags=["System"])
async def get_stats():
    """Get current API statistics"""
    with results_lock:
        s = dict(stats)
    
    return {
        "processed": s.get("processed", 0),
        "successful": s.get("successful", 0),
        "failed": s.get("failed", 0),
        "duplicates_skipped": s.get("duplicates", 0),
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "cache_size": len(token_cache) if 'token_cache' in dir() else 0,
    }

@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    executor.shutdown(wait=True)
    logger.info("API shutdown complete")