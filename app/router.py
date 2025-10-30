from datetime import datetime, timedelta, timezone
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, HTTPException, status, Header

from . import schemas, utils
from .database import get_db_connection

router = APIRouter(prefix="/api/v1/auth", tags=["Autenticação"])

LIMITE_TENTATIVAS_LOGIN = 3
BLOQUEIO_SEGUNDOS = 600

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
    
    query_users = """
    INSERT INTO users (email, doc_number, password, username, full_name, loggedin, created_at, updated_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
    """
    
    query_attempts = """
    INSERT INTO login_attempts (email, failed_attempts, block_expires_at)
    VALUES (%s, 0, NULL)
    ON CONFLICT (email) DO NOTHING;
    """
    
    token = utils.generate_token(user_data.email, user_data.doc_number)
    
    try:
        cursor.execute(query_users, (
            user_data.email, user_data.doc_number, user_data.password, user_data.username,
            user_data.full_name, False, now, now
        ))
        id_user = cursor.fetchone()['id']
        
        cursor.execute("INSERT INTO tokens (id_user, token, created_at) VALUES (%s, %s, %s)", (id_user, token, now))
        
        cursor.execute(query_attempts, (user_data.email,))
        
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

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    email = login_data.email.lower()
    now = datetime.now(timezone.utc)

    try:
        cursor.execute("SELECT * FROM login_attempts WHERE email = %s", (email,))
        login_attempt_data = cursor.fetchone()

        if login_attempt_data and login_attempt_data["block_expires_at"] and login_attempt_data["block_expires_at"] > now:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Muitas tentativas de login. Tente novamente mais tarde."
            )
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user or user["password"] != login_data.password:

            current_failures = 1
            if login_attempt_data:
                current_failures = login_attempt_data["failed_attempts"] + 1

            if current_failures >= LIMITE_TENTATIVAS_LOGIN:
                block = now + timedelta(seconds=BLOQUEIO_SEGUNDOS)

                query_lock = """
                INSERT INTO login_attempts(email, failed_attempts, block_expires_at)
                VALUES (%s, 0, %s)
                ON CONFLICT (email) DO UPDATE SET
                    failed_attempts = 0,
                    block_expires_at = %s
                """

                cursor.execute(query_lock, (email, block, block))
                conn.commit()

                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Muitas tentativas de login. Tente novamente em {BLOQUEIO_SEGUNDOS/60} minutos."
                )
            
            else:
                query_fail = """
                INSERT INTO login_attempts (email, failed_attempts, block_expires_at)
                VALUES (%s, %s, NULL)
                ON CONFLICT (email) DO UPDATE SET
                    failed_attempts = %s,
                    block_expires_at = NULL;
                """

                cursor.execute(query_fail, (email, current_failures, current_failures))
                conn.commit()

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="email ou senha inválidos."
                )
            
        if login_attempt_data:
            cursor.execute("DELETE FROM login_attempts WHERE email = %s", (email,))

        now_update = datetime.now()
        cursor.execute("UPDATE users SET loggedin = TRUE, updated_at = %s WHERE id = %s", (now_update, user["id"]))

        token = utils.generate_token(user["email"], user["doc_number"])
        cursor.execute("DELETE FROM tokens WHERE id_user = %s", (user["id"],))
        cursor.execute("INSERT INTO tokens (id_user, token, created_at) VALUES (%s, %s, %s)", (user["id"], token, now_update))
        conn.commit()

        return {"token": token, "mensagem": "login realizado"}
    
    finally:
        cursor.close()
        conn.close()
                            

@router.post("/recuperar-senha")
def recover_pass(recovery_data: schemas.PassRecovery):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    

    try:
        cursor.execute("SELECT id, email, doc_number FROM users WHERE email = %s AND doc_number = %s",
                       (recovery_data.email, recovery_data.document))
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
        
        now = datetime.now(timezone.utc)
        cursor.execute("UPDATE users SET password = %s, updated_at = %s WHERE id = %s",
                       (recovery_data.new_pass, now, user["id"]))
        
        token = utils.generate_token(user["email"], user["doc_number"])
        cursor.execute("DELETE FROM tokens WHERE id_user = %s", (user["id"],))
        cursor.execute("INSERT INTO tokens (id_user, token, created_at) VALUES (%s, %s, %s)", (user["id"], token, now))

        conn.commit()

        return {"token": token, "mensagem": "senha atualizada com sucesso"}

    finally:
        cursor.close()
        conn.close()


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(authorization: str = Header(...)):
    try:
        token_type, token = authorization.split()
        if token_type.lower() != "sdwork": raise ValueError
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Formato inválido")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cursor.execute("SELECT id_user FROM tokens WHERE token = %s", (token,))
        token_data = cursor.fetchone()

        if not token_data:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="token inválido")
        
        cursor.execute("DELETE FROM tokens WHERE token = %s", (token,))
        cursor.execute("UPDATE users SET loggedin = FALSE WHERE id = %s", (token_data["id_user"],))
        conn.commit()
        
        return {"mensagem": "logout realizado"}
    
    finally:
        cursor.close()
        conn.close()


@router.get("/me", response_model=schemas.User)
def get_user_data(authorization: str = Header(...)):
    try:
        token_type, token = authorization.split()
        if token_type.lower() != "sdwork": raise ValueError
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Formato do cabeçalho inválido.")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        query = """
        SELECT u.* FROM users u JOIN tokens t ON u.id = t.id_user WHERE t.token = %s
        """
        cursor.execute(query, (token,))
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="token inválido")
        
        return user

    finally:
        cursor.close()
        conn.close()