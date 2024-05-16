from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import List
from datetime import datetime
import httpx
import uvicorn
import asyncio

app = FastAPI()

class FixedVersionsResponse(BaseModel):
    name: str
    versions: List[str]
    timestamp: str

class OSVQuery(BaseModel):
    commit: str = None
    version: str = None
    package: dict
    pageToken: str = None

OSV_API_URL = "https://api.osv.dev/v1/query"

async def fetch_fixed_versions(package_name: str, ecosystems: List[str]) -> List[str]:
    async with httpx.AsyncClient() as client:
        tasks = [fetch_fixed_versions_for_ecosystem(client, package_name, ecosystem) for ecosystem in ecosystems]
        results = await asyncio.gather(*tasks)
        # Collect fixed versions from the async generators
        fixed_versions = []
        for result in results:
            async for version in result:
                fixed_versions.append(version)
        return list(set(fixed_versions))


async def fetch_fixed_versions_for_ecosystem(client, package_name: str, ecosystem: str) -> List[str]:
    query_payload = OSVQuery(package={"name": package_name, "ecosystem": ecosystem})
    data = await query_osv_api(client, query_payload)
    return extract_fixed_versions(data)

async def query_osv_api(client, query_payload: OSVQuery) -> dict:
    response = await client.post(OSV_API_URL, json=query_payload.dict())
    response.raise_for_status()
    return response.json()

async def extract_fixed_versions(data: dict) -> List[str]:
    for vuln in data.get('vulns', []):
        for affected in vuln.get('affected', []):
            for range_ in affected.get('ranges', []):
                for event in range_.get('events', []):
                    fixed_version = event.get('fixed')
                    if fixed_version:
                        yield fixed_version

@app.get("/fixed-versions", response_model=FixedVersionsResponse)
async def get_fixed_versions(name: str = Query(..., min_length=1), ecosystems: List[str] = Query([ "Ubuntu"])):
    fixed_versions = await fetch_fixed_versions(name, ecosystems)
    if not fixed_versions:
        raise HTTPException(status_code=404, detail="No fixed versions found")

    fixed_versions = sorted(fixed_versions, reverse=False)
    response = FixedVersionsResponse(
        name=name,
        versions=fixed_versions,
        timestamp=datetime.now().isoformat()
    )

    return response

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
