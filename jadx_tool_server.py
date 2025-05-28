"""
title:        JADX Tool Server
author:       Hacktify Cyber Security LLP
author_url:   https://hacktify.in
git_url:      https://github.com/your-repo/jadx-tool-server
description:  Exposes JADX-GUI reverse-engineering helpers as OpenAPI endpoints for Open WebUI / Llama.
required_open_webui_version: 0.6.0
requirements: fastapi, uvicorn, httpx
version:      1.0.0
license:      MIT
"""

import time
import random
import logging
from typing import List, Dict, Optional, Tuple, Union

import httpx
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Basic settings
# ---------------------------------------------------------------------------
JADX_HTTP_BASE = "http://127.0.0.1:8650"        # JADX-AI plugin base
CACHE_EXPIRY    = 300                           # seconds

app = FastAPI(
    title="JADX-AI Tool Server",
    version="1.0.0",
    description="REST wrapper around JADX-AI-MCP plugin; ready for Open WebUI.",
)

# ---------------------------------------------------------------------------
# Simple in-memory cache
# ---------------------------------------------------------------------------
_CacheType = Dict[str, Tuple[float, List[str]]]
_cache: _CacheType = {}

def _get_from_cache(key: str) -> Optional[List[str]]:
    now = time.time()
    if key in _cache:
        ts, data = _cache[key]
        if now - ts < CACHE_EXPIRY:
            return data
        del _cache[key]

    # Opportunistic cleanup (~10 % of calls)
    if random.random() < 0.1:
        expired = [k for k, (ts, _) in _cache.items() if now - ts >= CACHE_EXPIRY]
        for k in expired:
            del _cache[k]
    return None


def _set_cache(key: str, data: List[str]) -> None:
    _cache[key] = (time.time(), data)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
logger = logging.getLogger("jadx-tool-server")
logger.setLevel(logging.INFO)

async def _jadx_get(endpoint: str, params: dict | None = None) -> Union[str, dict]:
    """Generic wrapper for GET calls to the JADX-AI plugin."""
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(f"{JADX_HTTP_BASE}/{endpoint}", params=params or {})
            resp.raise_for_status()
            return resp.text
    except httpx.HTTPStatusError as e:
        logger.error("HTTP %s – %s", e.response.status_code, e.response.text)
        raise HTTPException(e.response.status_code, e.response.text)
    except httpx.RequestError as e:
        logger.error("Request error – %s", e)
        raise HTTPException(503, str(e))
    except Exception as e:                    # noqa: BLE001
        logger.exception("Unexpected error")
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# End-points  (names match the original MCP tools)
# ---------------------------------------------------------------------------
@app.get("/fetch_current_class")
async def fetch_current_class() -> JSONResponse:
    return JSONResponse(await _jadx_get("current-class"))


@app.get("/get_selected_text")
async def get_selected_text() -> JSONResponse:
    return JSONResponse(await _jadx_get("selected-text"))


@app.get("/get_method_by_name")
async def get_method_by_name(
    class_name: str = Query(..., description="Class name"),
    method_name: str = Query(..., description="Method name"),
) -> JSONResponse:
    return JSONResponse(
        await _jadx_get("method-by-name", {"class": class_name, "method": method_name})
    )


@app.get("/get_all_classes")
async def get_all_classes(
    offset: int = Query(0, ge=0),
    count:  int = Query(0, ge=0),
) -> JSONResponse:
    cache_key = "all_classes"
    classes = _get_from_cache(cache_key)
    if classes is None:
        raw = await _jadx_get("all-classes")
        import json
        try:
            classes = json.loads(raw).get("classes", [])
        except Exception:                     # noqa: BLE001
            classes = []
        _set_cache(cache_key, classes)

    sliced = classes[offset : (offset + count) if count else None]
    return JSONResponse(sliced)


@app.get("/get_class_source")
async def get_class_source(class_name: str = Query(...)) -> JSONResponse:
    return JSONResponse(await _jadx_get("class-source", {"class": class_name}))


@app.get("/search_method_by_name")
async def search_method_by_name(
    method_name: str = Query(...),
    offset: int = Query(0, ge=0),
    count:  int = Query(0, ge=0),
) -> JSONResponse:
    cache_key = f"search_method_{method_name}"
    matches = _get_from_cache(cache_key)
    if matches is None:
        text = await _jadx_get("search-method", {"method": method_name})
        matches = text.splitlines() if isinstance(text, str) else []
        _set_cache(cache_key, matches)
    sliced = matches[offset : (offset + count) if count else None]
    return JSONResponse(sliced)


@app.get("/get_methods_of_class")
async def get_methods_of_class(
    class_name: str = Query(...),
    offset: int = Query(0, ge=0),
    count:  int = Query(0, ge=0),
) -> JSONResponse:
    cache_key = f"methods_of_class_{class_name}"
    methods = _get_from_cache(cache_key)
    if methods is None:
        text = await _jadx_get("methods-of-class", {"class": class_name})
        methods = text.splitlines() if isinstance(text, str) else []
        _set_cache(cache_key, methods)
    sliced = methods[offset : (offset + count) if count else None]
    return JSONResponse(sliced)


@app.get("/get_fields_of_class")
async def get_fields_of_class(
    class_name: str = Query(...),
    offset: int = Query(0, ge=0),
    count:  int = Query(0, ge=0),
) -> JSONResponse:
    cache_key = f"fields_of_class_{class_name}"
    fields = _get_from_cache(cache_key)
    if fields is None:
        text = await _jadx_get("fields-of-class", {"class": class_name})
        fields = text.splitlines() if isinstance(text, str) else []
        _set_cache(cache_key, fields)
    sliced = fields[offset : (offset + count) if count else None]
    return JSONResponse(sliced)


@app.get("/get_smali_of_class")
async def get_smali_of_class(class_name: str = Query(...)) -> JSONResponse:
    return JSONResponse(await _jadx_get("smali-of-class", {"class": class_name}))


@app.get("/get_android_manifest")
async def get_android_manifest() -> JSONResponse:
    return JSONResponse(await _jadx_get("manifest"))


@app.get("/get_strings")
async def get_strings() -> JSONResponse:
    return JSONResponse(await _jadx_get("strings"))


@app.get("/get_all_resource_file_names")
async def get_all_resource_file_names() -> JSONResponse:
    return JSONResponse(await _jadx_get("list-all-resource-files-names"))


@app.get("/get_resource_file")
async def get_resource_file(resource_name: str = Query(...)) -> JSONResponse:
    return JSONResponse(await _jadx_get("get-resource-file", {"name": resource_name}))


@app.get("/get_main_application_classes_names")
async def get_main_application_classes_names(
    offset: int = Query(0, ge=0), count: int = Query(0, ge=0)
) -> JSONResponse:
    cache_key = "main_app_cls_names"
    names = _get_from_cache(cache_key)
    if names is None:
        raw = await _jadx_get("main-application-classes-names")
        import json
        try:
            parsed = json.loads(raw)
            names = [c["name"] for c in parsed.get("classes", [])]
        except Exception:                     # noqa: BLE001
            names = []
        _set_cache(cache_key, names)
    sliced = names[offset : (offset + count) if count else None]
    return JSONResponse(sliced)


@app.get("/get_main_application_classes_code")
async def get_main_application_classes_code(
    offset: int = Query(0, ge=0), count: int = Query(0, ge=0)
) -> JSONResponse:
    cache_key = "main_app_cls_code"
    sources = _get_from_cache(cache_key)
    if sources is None:
        raw = await _jadx_get("main-application-classes-code")
        import json
        try:
            sources = json.loads(raw).get("allClassesInPackage", [])
        except Exception:                     # noqa: BLE001
            sources = []
        _set_cache(cache_key, sources)
    sliced = sources[offset : (offset + count) if count else None]
    return JSONResponse(sliced)


@app.get("/get_main_activity_class")
async def get_main_activity_class() -> JSONResponse:
    return JSONResponse(await _jadx_get("main-activity"))


# ---------------------------------------------------------------------------
# Health-check
# ---------------------------------------------------------------------------
@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("jadx_tool_server:app", host="0.0.0.0", port=8000, reload=True)

