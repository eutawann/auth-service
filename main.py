# main.py

from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.router import router
from app.database import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("Banco de dados pronto.")
    
    yield
    
app = FastAPI(
    title="Microsserviço de Autenticação",
    lifespan=lifespan
)

app.include_router(router)

@app.get("/", tags=["Root"])
def read_root():
    return {"status": "Serviço de autenticação rodando"}
