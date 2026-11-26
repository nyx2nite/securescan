from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.routes import router
from app.tools import router as tools_router
from app.db.database import engine, Base

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecureScan")

app.add_middleware(GZipMiddleware, minimum_size=1024)
# Only needed for `npm run dev` on the Vite port; the desktop app is same-origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")
app.include_router(tools_router, prefix="/api")
