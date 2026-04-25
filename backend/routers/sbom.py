"""
Software Provenance Tracker — SBOM API Router

Exposes REST endpoints for SBOM (Software Bill of Materials) generation:
  - GET  /generate/{scan_id} — generate CycloneDX 1.4 JSON SBOM
  - GET  /download/{scan_id} — download SBOM as a .json file
"""

import json
import logging

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response

from sbom.sbom_generator import SbomGenerator
from db.postgres import PostgresManager
from db.redis_conn import RedisManager
from typosquat.typosquat_detector import TyposquatDetector
from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.sbom")

router = APIRouter(
    prefix="/api/sbom",
    tags=["sbom"],
    dependencies=[Depends(verify_api_key)],
)

# ─── Engine Instance ──────────────────────────────────────────

_generator: SbomGenerator | None = None


def setup_sbom_engine(
    postgres: PostgresManager,
    redis: RedisManager,
    typosquat_detector: TyposquatDetector | None = None,
) -> None:
    """Initialize the SBOM generator. Called during app startup."""
    global _generator
    _generator = SbomGenerator(
        postgres=postgres,
        redis=redis,
        typosquat_detector=typosquat_detector,
    )
    logger.info("SBOM engine initialized")


def cleanup_sbom_engine() -> None:
    """Clean up the SBOM generator. Called during app shutdown."""
    global _generator
    _generator = None
    logger.info("SBOM engine closed")


def _get_generator() -> SbomGenerator:
    """Get the generator instance, raising if not initialized."""
    if _generator is None:
        raise HTTPException(
            status_code=503,
            detail="SBOM engine not initialized",
        )
    return _generator


def get_sbom_generator() -> SbomGenerator | None:
    """Public getter for the SBOM generator."""
    return _generator


# ─── Endpoints ────────────────────────────────────────────────

@router.get("/generate/{scan_id}")
async def generate_sbom(scan_id: int):
    """
    Generate a CycloneDX 1.4 SBOM for a completed scan.

    Returns the full SBOM as a JSON response, including:
      - All components (packages) with purls, licenses, hashes
      - Dependency graph
      - CVE vulnerabilities (if available)
      - Provenance metadata (anomaly scores, flags, typosquat checks)
    """
    generator = _get_generator()

    try:
        bom = await generator.generate_from_scan(scan_id)
        return bom

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"SBOM generation failed for scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"SBOM generation failed: {str(e)}",
        )


@router.get("/download/{scan_id}")
async def download_sbom(scan_id: int):
    """
    Download a CycloneDX 1.4 SBOM as a .json file.

    Returns the SBOM as an attachment with Content-Disposition
    header set for file download.
    """
    generator = _get_generator()

    try:
        bom = await generator.generate_from_scan(scan_id)

        # Serialize with indentation for readability
        content = json.dumps(bom, indent=2, default=str)
        filename = f"sbom-scan-{scan_id}.cdx.json"

        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"SBOM download failed for scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"SBOM download failed: {str(e)}",
        )
