from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, HTTPException, status, Header

from . import schemas, utils
from .database import get_db_connection

router = APIRouter(prefix="/api/v1/auth", tags=["Autenticação"])

@router.post("/signup", status_code=status.HTTP_201_CREATED)
def create_new_account(user_data: schemas.User):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    now = datetime.now()


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
    try:
        cursor.execute(query, (
            user_data.email, user_data.doc_number, user_data.password, user_data.username,
            user_data.full_name, False, now, now
        ))
        id_user = cursor.fetchone()['id']
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email ou documento já cadastrado")
    finally:
        cursor.close()
        conn.close()

    token = utils.generate_token(user_data.email, user_data.doc_number)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tokens (id_user, token, created_at) VALUES (%s, %s, %s)", (id_user, token, now))
    conn.commit()
    cursor.close()
    conn.close()

    return {"token": token}

@router.post("/login")
def login(login_data: schemas.UserLogin):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE email = %s", (login_data.email,))
    user = cursor.fetchone()

    if not user or user["password"] != login_data.password:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email ou senha inválidos")
    
    now = datetime.now()
    cursor.execute("UPDATE users SET loggedin = TRUE, updated_at = %s WHERE id = %s", (now, user['id']))

    token = utils.generate_token(user["email"], user["doc_number"])
    cursor.execute("DELETE FROM tokens WHERE id_user = %s", (user["id"],))
    cursor.execute("INSERT INTO tokens (id_user, token, created_at) VALUES (%s, %s, %s)", (user["id"], token, now))

    conn.commit()
    cursor.close()
    conn.close()

    return {"token": token, "mensagem": "login realizado"}

@router.post("/recuperar-senha")
def recover_pass(recovery_data: schemas.PassRecovery):

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    cursor.execute("SELECT id, email, doc_number FROM users WHERE email = %s AND doc_number = %s",
                   (recovery_data.email, recovery_data.document))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    
    now = datetime.now()
    cursor.execute("UPDATE users SET password = %s, updated_at = %s WHERE id = %s",
                   (recovery_data.new_pass, now, user["id"]))
    
    token = utils.generate_token(user["email"], user["doc_number"])
    cursor.execute("DELETE FROM tokens WHERE id_user = %s", (user["id"],))
    cursor.execute("INSERT INTO tokens (id_user, token, created_at) VALUES (%s, %s, %s)", (user["id"], token, now))

    conn.commit()
    cursor.close()
    conn.close()

    return {"token": token, "mensagem": "senha atualizada com sucesso"}


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(authorization: str = Header(...)):
    try:
        token_type, token = authorization.split()
        if token_type.lower() != "sdwork": raise ValueError
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Formato inválido")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT id_user FROM tokens WHERE token = %s", (token,))
    token_data = cursor.fetchone()

    if not token_data:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="token inválido")
    
    cursor.execute("DELETE FROM tokens WHERE token = %s", (token,))
    cursor.execute("UPDATE users SET loggedin = FALSE WHERE id = %s", (token_data["id_user"],))
    conn.commit()
    cursor.close()
    conn.close()
    
    return {"mensagem": "logout realizado"}


@router.get("/me", response_model=schemas.User)
def get_user_data(authorization: str = Header(...)):
    try:
        token_type, token = authorization.split()
        if token_type.lower() != "sdwork": raise ValueError
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Formato do cabeçalho inválido.")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    query = """
    SELECT u.* FROM users u JOIN tokens t ON u.id = t.id_user WHERE t.token = %s
    """

    cursor.execute(query, (token,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="token inválido")
    
    return user