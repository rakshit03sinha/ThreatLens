"""ThreatLens Main Application and Lifespan."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.session import async_session_factory, close_db, init_db
from app.models.investigation import Playbook
from app.models.rule import DetectionRule
from app.models.user import User
from app.rules.catalogue import ALL_RULES
from app.workers.pipeline import worker_queue

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("threatlens")

STATIC_DIR = Path(__file__).parent / "static"


async def seed_initial_metadata():
    """Ensure initial admin user, 11 detection rules, and incident playbooks exist in DB."""
    async with async_session_factory() as session:
        try:
            # 1. Admin User
            admin_stmt = select(User).where(User.username == settings.ADMIN_USERNAME)
            admin = (await session.execute(admin_stmt)).scalars().first()
            if not admin:
                new_admin = User(
                    username=settings.ADMIN_USERNAME,
                    email=settings.ADMIN_EMAIL,
                    hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                    role="admin",
                    is_active=True,
                )
                session.add(new_admin)
                logger.info(f"Created default admin user: {settings.ADMIN_USERNAME}")

            # 2. Sync all 11 detection rules
            for rule in ALL_RULES:
                r_stmt = select(DetectionRule).where(DetectionRule.rule_id == rule.rule_id)
                db_rule = (await session.execute(r_stmt)).scalars().first()
                if not db_rule:
                    session.add(
                        DetectionRule(
                            rule_id=rule.rule_id,
                            name=rule.name,
                            description=rule.description,
                            severity=rule.severity,
                            status="enabled",
                            tactic=rule.attack_tactic,
                            technique_id=rule.attack_technique,
                            technique_name=rule.attack_technique_name,
                            window_seconds=rule.default_window_seconds,
                            threshold=rule.default_threshold,
                            version=rule.version,
                            parameters={},
                        )
                    )

            # 3. Default SOC Runbooks/Playbooks
            playbooks_data = [
                {
                    "id": "PB-BRUTE-FORCE",
                    "title": "Brute Force & Credential Guessing Response",
                    "category": "Credential Access",
                    "technique": "T1110",
                    "desc": "Standard operating procedure for responding to automated or targeted credential attacks.",
                    "triage": [
                        "Verify whether any attempts succeeded after failure burst.",
                        "Correlate source IP with Threat Intelligence feeds.",
                        "Inspect target account privileges (admin, service, standard).",
                    ],
                    "containment": [
                        "Block external source IP at perimeter firewall.",
                        "Temporarily disable or force credential reset on targeted user account.",
                        "Revoke active session tokens for the affected account.",
                    ],
                    "remediation": [
                        "Enforce MFA across affected application / gateway.",
                        "Review account lockout threshold policies.",
                    ],
                },
                {
                    "id": "PB-WEB-EXPLOIT",
                    "title": "Web Application Exploit & Path Traversal Response",
                    "category": "Initial Access",
                    "technique": "T1190",
                    "desc": "Response runbook for URI traversal, LFI, and SQL injection probes.",
                    "triage": [
                        "Review HTTP status code returned (403/404 vs 200 OK).",
                        "Check web application error logs for stack trace disclosures.",
                    ],
                    "containment": [
                        "Block client IP at Web Application Firewall (WAF).",
                        "Apply virtual patch on WAF for traversed pattern.",
                    ],
                    "remediation": [
                        "Sanitize file path handling and apply input validation.",
                        "Harden file permissions on web server root directory.",
                    ],
                },
                {
                    "id": "PB-C2-EGRESS",
                    "title": "Command and Control (C2) / Reverse Shell Response",
                    "category": "Command and Control",
                    "technique": "T1071",
                    "desc": "Runbook for outbound beaconing or connections to high-risk non-standard ports.",
                    "triage": [
                        "Identify initiating endpoint process and parent PID.",
                        "Inspect outbound destination IP reputation and autonomous system (ASN).",
                    ],
                    "containment": [
                        "Isolate infected endpoint from internal LAN.",
                        "Sinkhole destination domain / block destination IP.",
                    ],
                    "remediation": [
                        "Terminate malicious process tree.",
                        "Perform full forensic memory analysis and eradicate persistence mechanisms.",
                    ],
                },
            ]

            for pb in playbooks_data:
                pb_stmt = select(Playbook).where(Playbook.playbook_id == pb["id"])
                existing_pb = (await session.execute(pb_stmt)).scalars().first()
                if not existing_pb:
                    session.add(
                        Playbook(
                            playbook_id=pb["id"],
                            title=pb["title"],
                            category=pb["category"],
                            attack_technique=pb["technique"],
                            description=pb["desc"],
                            triage_steps=pb["triage"],
                            containment_steps=pb["containment"],
                            remediation_steps=pb["remediation"],
                        )
                    )

            await session.commit()
            logger.info("Successfully verified database metadata (rules, playbooks, admin).")
        except Exception as e:
            await session.rollback()
            logger.error(f"Error during metadata seeding: {str(e)}", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and graceful shutdown."""
    logger.info("Starting ThreatLens SIEM Engine...")
    await init_db()
    await seed_initial_metadata()
    await worker_queue.start()
    yield
    logger.info("Shutting down ThreatLens SIEM Engine...")
    await worker_queue.stop()
    await close_db()


app = FastAPI(
    title="ThreatLens",
    version=settings.APP_VERSION,
    description="AI-Powered SIEM & Threat Detection Platform aligned with MITRE ATT&CK.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Safe Error Handler to prevent leaking internal stack traces
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "An internal server error occurred. Please contact the SOC administrator.", "success": False},
    )


# Mount Static Assets and Dashboard
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(STATIC_DIR / "index.html")


# Include API v1 Router
app.include_router(api_router, prefix="/api/v1")
