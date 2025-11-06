import os
from dotenv import load_dotenv
import redis

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

try:
    pool = redis.ConnectionPool.from_url(REDIS_URL)

except Exception as e:
    print(f"Erro ao criar: {e}")
    pool = None

def get_redis_connection():

    if pool is None:
        raise Exception("Pool de conexões")
    
    return redis.Redis(connection_pool=pool)