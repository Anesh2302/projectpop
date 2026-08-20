import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if os.environ.get("VERCEL"):
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url or db_url.startswith("sqlite"):
        pg_url = os.environ.get("POSTGRES_URL_NON_POOLING") or os.environ.get("POSTGRES_URL") or ""
        if pg_url and pg_url.startswith("postgres"):
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(pg_url)
            os.environ["DATABASE_URL"] = urlunparse(parsed._replace(scheme="postgresql"))
        else:
            os.environ["DATABASE_URL"] = "sqlite:////tmp/projectpop.db"
    if not os.environ.get("SECRET_KEY"):
        os.environ["SECRET_KEY"] = "projectpop-vercel-prod-key"

from app import create_app

app = create_app()
