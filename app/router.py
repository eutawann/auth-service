from datetime import datetime, timedelta, timezone
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, HTTPException, status, Header
import redis



from . import schemas, utils
from .database import get_db_connection
from .redis_client import get_redis_connection

router = APIRouter(prefix="/api/v1/auth", tags=["Autenticação"])

LIMITE_TENTATIVAS_LOGIN = 3
BLOQUEIO_SEGUNDOS = 15

LIMITE_REQUISICOES = 20
LIMITE_SEGUNDOS = 60

TOKEN_EXPIRA = 900 #15min

@router.post("/signup", status_code=status.HTTP_201_CREATED)
def create_new_account(user_data: schemas.User):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    now = datetime.now(timezone.utc)

    if not all([user_data.doc_number, user_data.password, user_data.username, user_data.full_name]):
        cursor.close()
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Campos obrigatórios ausentes: email, doc_number, password, username, full_name"
        )
    
    query = """
    INSERT INTO users (email, doc_number, password, username, full_name, loggedin, created_at, updated_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
    """
    
    token = utils.generate_encrypted_token(user_data.email, user_data.doc_number)
    
    try:
        cursor.execute(query, (
            user_data.email, user_data.doc_number, user_data.password, user_data.username,
            user_data.full_name, False, now, now
        ))
        id_user = cursor.fetchone()['id']
        
        cursor.execute("INSERT INTO tokens (id_user, token, created_at) VALUES (%s, %s, %s)", (id_user, token, now))
        
        conn.commit()

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email ou documento já cadastrado")
    finally:
        cursor.close()
        conn.close()

    return {"token": token}

@router.post("/login")
def login(login_data: schemas.UserLogin):

    try:
        r = get_redis_connection()

    except Exception as e:
        raise HTTPException(status_code=503, detail="indisponível.")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    email = login_data.email.lower()
    block_key = f"bloqueio:{email}"
    failure_key = f"falha:{email}"

    try:
        if r.exists(block_key):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Muitas tentativas de login. Tente novamente em 10 minutos."
            )
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user or user["password"] != login_data.password:
            current_failures = r.incr(failure_key)
            if current_failures >= LIMITE_TENTATIVAS_LOGIN:
                r.set(block_key, 1, ex=BLOQUEIO_SEGUNDOS)
                r.delete(failure_key)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Muitas tentativas de login. Tente novamente em 10 minutos."
                )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="email ou senha inválidos."
            )
        
        r.delete(failure_key)

        now = datetime.now(timezone.utc)
        cursor.execute("UPDATE users SET loggedin = TRUE, updated_at = %s WHERE id = %s", (now, user['id']))

        token = utils.generate_encrypted_token(user["email"], user["doc_number"])

        cursor.execute("DELETE FROM tokens WHERE id_user = %s", (user["id"],))
        cursor.execute("INSERT INTO tokens (id_user, token, created_at) VALUES (%s, %s, %s)", (user["id"], token, now))

        conn.commit()

        return {"token": token, "mensagem": "login realizado"}

    finally:
        cursor.close()
        conn.close()
        r.close() 

@router.post("/esqueci-senha")
def request_pass_reset(request_data: schemas.PassForgotRequest):
    email = request_data.email.lower()

    conn_pg = None
    r = None

    try:
        conn_pg = get_db_connection()
        cursor = conn_pg.cursor(cursor_factory=RealDictCursor)

        cursor.execute("SELECT id FROM USERS  WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            try:
                r = get_redis_connection()
                reset_token = utils.generate_reset_token()
                redis_key = f"reset:{reset_token}"

                r.set(redis_key, email, ex=TOKEN_EXPIRA)

                print(f"Token de reset para {email}: {reset_token}")
                
                return {
                    "mensagem": "Se um usuário com este email existir, um token de reset foi gerado.",
                    "reset_token_simulado": reset_token 
                }

            except Exception as e:
                print(f"Erro de Redis em /esqueci-senha: {e}")
                raise HTTPException(status_code=503, detail="Serviço indisponível.")

        return {"mensagem": "token gerado."}

    finally:
        if r:
            r.close()
        if conn_pg:
            cursor.close()
            conn_pg.close()

@router.post("/resetar-senha")
def execute_password_reset(request_data: schemas.PassResetRequest):

    token = request_data.token
    new_pass = request_data.new_pass
    redis_key = f"reset:{token}"

    conn_pg = None
    r = None

    try:
        r = get_redis_connection()

        email_bytes = r.get(redis_key)

        if email_bytes is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token de reset inválido ou expirado")
        
        email = email_bytes.decode('utf-8')

        r.delete(redis_key)

        conn_pg = get_db_connection()
        cursor = conn_pg.cursor()
        now = datetime.now(timezone.utc)

        cursor.execute("UPDATE users SET password = %s, updated_at = %s WHERE email = %s",
                       (new_pass, now, email))
        conn_pg.commit()
        
        return {"mensagem": "Senha atualizada com sucesso."}

    finally:
        if r:
            r.close()
        if conn_pg:
            cursor.close()
            conn_pg.close()

@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(authorization: str = Header(...)):
    
    token_str = None
    payload = None

    try:
        token_type, token_str = authorization.split()
        if token_type.lower() != "sdwork": raise ValueError
        
        payload = utils.decrypt_and_validate_token(token_str)
        if payload is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido ou corrompido")

    except (ValueError, HTTPException):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Formato do cabeçalho ou token inválido")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:

        cursor.execute("SELECT id_user FROM tokens WHERE token = %s", (token_str,))
        token_data = cursor.fetchone()

        if not token_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token não encontrado ou já deslogado")
        
        id_user = token_data["id_user"]
        cursor.execute("DELETE FROM tokens WHERE token = %s", (token_str,))
        cursor.execute("UPDATE users SET loggedin = FALSE WHERE id = %s", (id_user,))
        conn.commit()
        
        return {"mensagem": "logout realizado"}
    
    finally:
        cursor.close()
        conn.close()


@router.get("/me", response_model=schemas.User)
def get_user_data(authorization: str = Header(...)):
    
    email = None
    token_str = None
    
    try:
        token_type, token_str = authorization.split()
        if token_type.lower() != "sdwork": raise ValueError
        
        payload = utils.decrypt_and_validate_token(token_str)
        if payload is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido, corrompido ou expirado")
            
        email = payload.get("email")
        
    except (ValueError, HTTPException):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Formato do cabeçalho ou token inválido")
    
    conn_pg = None
    cursor = None
    r = None
    
    try:
        r = get_redis_connection()
        key = f"throttle:me:{email}"
        
        p = r.pipeline()
        p.incr(key) 
        p.expire(key, LIMITE_SEGUNDOS, nx=True) 
        results = p.execute() 
        current_count = results[0]

        if current_count > LIMITE_REQUISICOES:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Limite de requisições excedido."
            )

        conn_pg = get_db_connection()
        cursor = conn_pg.cursor(cursor_factory=RealDictCursor)
        
        query_user = """
        SELECT u.* FROM users u JOIN tokens t ON u.id = t.id_user 
        WHERE t.token = %s AND u.email = %s
        """
        cursor.execute(query_user, (token_str, email))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token válido, mas não encontrado no banco (ex: deslogado)")
        
        return user

    finally:
        if r:
            r.close()
        if cursor:
            cursor.close() 
        if conn_pg:
            conn_pg.close()
