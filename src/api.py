from contextlib import asynccontextmanager
from uuid import UUID, uuid4
from typing import Annotated, Optional, List
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from backend import Account, Application, APIKey, Backend, KeyType, Permissions, StubUser, Transaction
from utils import resolve_mentions
from discord import Client

from fastapi import FastAPI, Request, HTTPException, Depends, Form, status
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.sessions import SessionMiddleware

import jwt
import secrets
import datetime, time
import json
import aiohttp
import os
import traceback
import cachetools
import uvicorn
import asyncio
import logging

logger = logging.getLogger(os.path.basename(__file__).split(".")[0])

API_URL = "https://discord.com/api/v10"
CALLBACK_URL = API_URL + "/oauth2/token"

trusted_public_keys = {}
private_key = ""

@asynccontextmanager
async def lifespan(_: FastAPI):
    global private_key

    with open("./keys/jwt_key", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), None)

    for issuer in os.listdir("./keys/public_keys/"):
        trusted_public_keys[issuer.split(".")[0]] = os.path.join("./keys/public_keys/", issuer)

    yield

app = FastAPI(lifespan=lifespan)
backend = Backend("")
client: Optional[Client] = None

try:
    with open("config.json") as file:
        config = json.load(file)
except Exception:
    traceback.print_exc()
    raise

app.mount("/static", StaticFiles(directory="static"), name="static")
app.add_middleware(SessionMiddleware, secret_key=config.get("session_key", "ABCDEF"), max_age=600)
templates = Jinja2Templates(directory="jinja_templates")

# Permissions that we currently allow applications to use
descriptions = {
    Permissions.VIEW_BALANCE: "Allows the application to view your account's balance",
    # Permissions.CLOSE_ACCOUNT: "Allows the application to close your account on your behalf",
    Permissions.TRANSFER_FUNDS: "Allows the application to transfer funds from your account",
    # Permissions.CREATE_RECURRING_TRANSFERS: "Allows the application to create recurring transfers on your behalf from your account's balance",
    # Permissions.MANAGE_FUNDS: "Allows the application to print and remove funds on your behalf",
    # Permissions.MANAGE_TAX_BRACKETS: "Allows the application to create, remove and perform tax brackets on your behalf",
    # Permissions.OPEN_SPECIAL_ACCOUNT: "Allows the application to open special accounts on your behalf"
}

# Taking some inspiration from Discord's own oauth integration, pass requirements as bitmask instead of json list or something like that because im too lazy to parse it
def get_permissions(bitmask: int) -> List[Permissions]:
    found = []
    for perm in descriptions.keys():
        if (bitmask >> perm.value) & 1:
            found.append(perm)
    return found

# Don't think this will do anything meaningful to the response, but it'll be good to debug the response time without having to profile
# https://fastapi.tiangolo.com/tutorial/middleware/#create-a-middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time"] = str(process_time)

    logger.info(f"{request.method} {request.url.path} | Time: {process_time:.4f}s")
    return response

# favicon
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("./static/favicon.png")

security = HTTPBearer(auto_error=False)

def generate_key(key_id: int, days_to_expire: int = 60):
    claims = {
        "sub": str(key_id),
        "iss": "TB",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_to_expire)
    }
    return jwt.encode(claims, private_key, algorithm="RS512") # type: ignore

def get_typed_key(*types: KeyType):
    async def get_key(cred: Optional[HTTPAuthorizationCredentials] = Depends(security)):
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired or disabled key"
        )

        if cred is None:
            raise exception

        key = cred.credentials

        try:
            payload = jwt.decode(key, options={"verify_signature": False, "require": ["sub", "iss"]})
            issuer = payload.get("iss")
            if not issuer:
                raise exception

            path = trusted_public_keys.get(issuer)
            if not path:
                raise exception

            with open(path, "r") as f:
                publiC_key = f.read()

            # https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
            # "The "sub" (subject) claim identifies the principal that is the subject of the JWT. The claims in a JWT are normally statements about the subject."
            claims = jwt.decode(key, publiC_key, algorithms=["RS512"])
            key_id = claims.get("sub")
            if not key_id:
                raise exception

        except jwt.exceptions.InvalidTokenError:
            raise exception

        try:
            key = await backend.get_key_by_id(int(key_id))
        except (TypeError, ValueError):
            raise exception
        else:
            if not key or (key and not key.enabled) or (key and key.type not in types):
                raise exception
            elif key.type == KeyType.GRANT and not key.account:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Grant keys must be linked to an account"
                )

        return key

    return get_key

class APIStubUser(StubUser):
    @classmethod
    def from_key(cls, key: APIKey):
        self = cls(key.key_id)
        self.mention = f"<@{key.issuer_id}>"
        return self

@app.get("/")
async def root():
    return {"detail": "Visit the documentation for more info."}

auth_store = cachetools.TTLCache(64, 3600) # apps have 1 hour to get their refs
@app.post("/api/references/register", status_code=status.HTTP_201_CREATED)
async def create_reference(permissions: int, key: Annotated[APIKey, Depends(get_typed_key(KeyType.MASTER, KeyType.GRANT))]):
    if key.type != KeyType.MASTER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="New references must be created using the original master key"
        )

    app_id = key.application_id
    if not auth_store.get(app_id):
        auth_store[app_id] = {}

    perms = []
    if permissions > 0:
        perms = get_permissions(permissions)
        if not perms:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Minimum permissions bitmask malformed or invalid"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide permissions"
        )

    ref_uuid = uuid4()
    auth_store[f"{app_id}:{ref_uuid}"] = {"ref_id": ref_uuid, "permissions": perms, "type": "create"}
    return {"uuid": ref_uuid}

@app.patch("/api/references/register")
async def update_reference(key: Annotated[APIKey, Depends(get_typed_key(KeyType.MASTER, KeyType.GRANT))], permissions: Optional[int] = None):
    if key.type != KeyType.GRANT:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Update references must be created using the original grant key"
        )

    app_id = key.application_id
    if not auth_store.get(app_id):
        auth_store[app_id] = {}

    perms = []
    if permissions and permissions > 0:
        perms = get_permissions(permissions)
        if not perms:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Permissions bitmask malformed or invalid"
            )

    ref_uuid = uuid4()
    auth_store[f"{app_id}:{ref_uuid}"] = {"ref_id": ref_uuid, "permissions": perms, "type": "update", "key": key}
    return {"uuid": ref_uuid}

@app.get("/api/references/{ref_id}")
async def get_key(ref_id: str, key: Annotated[APIKey, Depends(get_typed_key(KeyType.MASTER, KeyType.GRANT))]):
    app = key.application

    if ref_id.lower() == "register":
        raise HTTPException(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            detail="Method Not Allowed"
        )

    try:
        ref_uuid = UUID(ref_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reference UUID malformed or invalid"
        )

    authkey = f"{app.application_id}:{ref_uuid}"
    key_meta = auth_store.get(authkey)

    if not key_meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reference not registered"
        )

    data, type = key_meta.get("data"), key_meta.get("type")
    if not data or not type:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User has not yet authenticated using reference"
        )
    
    delete = False
    if type == "update":
        if key.type != KeyType.GRANT:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Update references must be retrieved using the original grant key"
            )
        delete = True
    elif type == "create" and key.type != KeyType.MASTER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="New references must be retrieved using the original master key"
        )

    new_key = await backend.create_key(app, key_meta["user"], key_meta["account"], data.spending_limit, enable_by_default=True)
    if delete:
        await backend.delete_key(APIStubUser.from_key(key), key)

    if (permissions := key_meta.get("permissions")):
        await backend.change_key_permissions(new_key, permissions, key_meta["account"])
    
    auth_store.pop(authkey, None)
    return {"key": generate_key(new_key.key_id, 90)} # IMPORTANT; grant keys last 90 days, master keys last 60 days

@app.get("/api/oauth/grant")
async def start_linking(ref_id: str, app_id: str, request: Request):
    try:
        ref_uuid = UUID(ref_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reference UUID malformed or invalid"
        )

    try:
        app_uuid = UUID(app_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Application UUID malformed or invalid"
        )
    else:
        app = await backend.get_application(app_uuid)
        if not app:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Application not found"
            )

    authkey = f"{app_uuid}:{ref_uuid}"
    if not authkey in auth_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unregistered reference, please contact the application"
        )

    redirect_url = config.get("oauth", {}).get("redirect_url")
    if not redirect_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth service unavailable"
        )

    state = secrets.token_urlsafe(32)
    res = RedirectResponse(redirect_url + f"&state={state}")
    
    request.session["state"] = state
    request.session["authkey"] = authkey

    return res

@app.get("/api/oauth/callback")
async def callback(code: str, state: str, request: Request):
    exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Something went wrong, please try logging in again"
    )

    oauth = config.get("oauth", {})
    client_id = oauth.get("client_id")
    client_secret = oauth.get("client_secret")

    if not (client_id and client_secret):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth service unavailable"
        )

    if state != request.session.get("state"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="State mismatch"
        )

    async with aiohttp.ClientSession() as session:
        auth = aiohttp.BasicAuth(client_id, client_secret)
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": oauth.get("redirect_uri")       
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        async with await session.post(CALLBACK_URL, auth=auth, data=data, headers=headers) as resp:
            if resp.status != 200:
                raise exception

            data = await resp.json()
            key = data.get("access_token")

    res = RedirectResponse(request.url_for("protected_grant"))
    authkey = request.session.get("authkey")
    request.session.clear() # regen session id
    request.session["user"] = await get_user_id(key)
    request.session["authkey"] = authkey

    return res

async def get_user_id(key: str):
    exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Something went wrong, please try logging in again"
    )

    async with aiohttp.ClientSession() as session:
        async with session.get(API_URL + "/users/@me", headers={"Authorization": f"Bearer {key}"}) as resp:
            if resp.status != 200:
                raise exception

            data = await resp.json()
#           print(data)
            return int(data.get("id"))

@app.get("/api/oauth/protected/grant", name="protected_grant")
async def protected_grant(request: Request):
    if not (authkey := request.session.get("authkey")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized access, please login again"
        )

    app_uuid = UUID(authkey.split(":")[0])
    user_id: int = request.session["user"]

    app = await backend.get_application(app_uuid)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )

    actor = await backend.get_member(user_id, app.economy.owner_guild_id)
    if not actor:
        actor = StubUser(user_id)

    req = auth_store.get(authkey)
    if req:
        if (type := req.get("type")) and type == "update":
            key: Optional[APIKey] = req.get("key")
            if not key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Unauthorized access, please re-authenticate with the application"
                )

            assert key.account # update refs will always be GRANT keys

            authable = [key.account]
            permissions = []
        elif (permissions := req.get("permissions")):
            authable = await backend.get_authable_accounts(actor, permissions)
        else:
            authable = []
            permissions = []

        if len(authable) > 0:
            return templates.TemplateResponse(
                request=request,
                name="grant_page.html", 
                context={
                    "accounts": authable, 
                    "permissions": [(p.name, descriptions[p]) for p in permissions],
                    "application_name": app.application_name,
                    "fetch_name": lambda name: resolve_mentions(name, client) if client else name
                }
            )
        else:
            return {"detail": "No authenticable accounts found. Please try again."}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized reference"
    )

class GrantForm(BaseModel):
    account: str
    spending_limit: Optional[int] = Form(None)
    no_limit: Optional[str] = Form(None)

@app.post("/api/oauth/submit")
async def submit(data: Annotated[GrantForm, Form()], request: Request):
    exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Something went wrong, please try logging in again"
    )

    if not (authkey := request.session.get("authkey")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized access, please login again"
        )
    elif authkey not in auth_store:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized application"
        )

    app_uuid = UUID(authkey.split(":")[0])
    user_id: int = request.session["user"]
    acc_id = UUID(data.account)

    app = await backend.get_application(app_uuid)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )
    
    meta = auth_store.get(authkey)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reference has not been registered"
        )
    elif (issuer := meta.get("issuer_id")) and issuer != user_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Reference has already been claimed"
        )

    granter = await backend.get_member(user_id, app.economy.owner_guild_id)
    if not granter:
        granter = StubUser(user_id)

    acc = await backend.get_account_by_id(acc_id)
    if not acc:
        raise exception

    authorized = False
    if (permissions := meta.get("permissions")):
        if all([v async for v in (await backend.has_permission(granter, p, acc) for p in permissions)]):
            auth_store[authkey].update({"user": granter.id, "data": data, "account": acc})
            authorized = True
    elif (type := meta.get("type")) and type == "update":
        auth_store[authkey].update({"user": granter.id, "data": data, "account": acc})
        authorized = True

    if authorized:
        return RedirectResponse(request.url_for("authorized"), status_code=status.HTTP_303_SEE_OTHER)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="You do not have the permissions required by the application for this account"
    )

@app.get("/api/oauth/authorized", name="authorized")
async def authorized(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="authorized.html"
    )

# == Endpoints ==

def encode_account(account: Account, show_bal: bool = False):
    return {
        "account_id": str(account.account_id),
        "owner_id": str(account.owner_id),
        "account_name": account.account_name,
        "account_type": account.account_type.name,
        "balance": account.balance if show_bal else None
    }

def encode_application(application: Application):
    return {
        "application_id": str(application.application_id),
        "application_name": application.application_name,
        "economy_name": application.economy.currency_name,
        "economy_id": str(application.economy_id),
        "owner_id": str(application.owner_id)
    }

def encode_key(key: APIKey):
    return {
        "id": str(key.key_id),
        "application_id": str(key.application_id),
        "type": key.type.name,
        "enabled": key.enabled
    }

def encode_transaction(t: Transaction):
    return {
        "actor_id": str(t.actor_id),
        "timestamp": t.timestamp.timestamp(),
        "from_account": str(t.target_account_id),
        "to_account": str(t.destination_account_id),
        "amount": t.amount
    }

@app.get("/api/applications/{app_id}")
async def get_application(app_id: str, key: Annotated[APIKey, Depends(get_typed_key(KeyType.MASTER, KeyType.GRANT))]):
    if app_id.lower() == "me":
        app = key.application
    else:
        try:
            app_uuid = UUID(app_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Application UUID malformed or invalid"
            )

        app = await backend.get_application(app_uuid)

    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )

    return encode_application(app)

@app.get("/api/applications/user/{user_id}")
async def get_user_application(user_id, key: Annotated[APIKey, Depends(get_typed_key(KeyType.MASTER, KeyType.GRANT))]):
    if not await backend.key_has_permission(key, Permissions.MANAGE_ECONOMIES, economy=key.application.economy):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have the permission to view user applications"
        )

    try:
        user_id = int(str(user_id))
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Non-integer user ID"
        )

    apps = await backend.get_user_applications(user_id)
    return [encode_application(app) for app in apps]

@app.get("/api/accounts")
async def get_account(key: Annotated[APIKey, Depends(get_typed_key(KeyType.MASTER, KeyType.GRANT))], user_id: Optional[str] = None, name: Optional[str] = None):
    if [user_id, name].count(None) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide only one of the following parameters: user_id, name"
        )

    if user_id:
        try:
            uid = int(str(user_id))
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Non-integer user ID"
            )

        acc = await backend.get_user_account(uid, key.application.economy)
    else:
        assert(name)
        acc = await backend.get_account_by_name(name, key.application.economy)

    if not acc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found"
        )

    show_bal = await backend.key_has_permission(key, Permissions.VIEW_BALANCE, account=acc)
    return encode_account(acc, show_bal)

@app.get("/api/accounts/{acc_id}")
async def get_account_by_id(acc_id: str, key: Annotated[APIKey, Depends(get_typed_key(KeyType.MASTER, KeyType.GRANT))]):
    try:
        acc_uuid = UUID(acc_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account UUID malformed or invalid"
        )

    acc = await backend.get_account_by_id(acc_uuid)
    if not acc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found"
        )

    show_bal = await backend.key_has_permission(key, Permissions.VIEW_BALANCE, account=acc)
    return encode_account(acc, show_bal)

class TransactionCreate(BaseModel):
    to_account_id: str
    amount: int

@app.post("/api/transactions/create")
async def new_transaction(data: TransactionCreate, key: Annotated[APIKey, Depends(get_typed_key(KeyType.GRANT))]):
    if data.amount < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Amount transferred must be greater than zero"
        )

    assert(key.account)

    try:
        to_uuid = UUID(data.to_account_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account UUID malformed or invalid"
        )

    to_acc = await backend.get_account_by_id(to_uuid)
    if not to_acc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="To account not found"
        )
    elif key.account.account_id == to_acc.account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": 1000,
                "detail": "Cannot transfer from and to the same account"
            }
        )
    elif key.account.balance < data.amount:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": 1001,
                "detail": "Insufficient funds"
            }
        )
    elif key.spending_limit and data.amount + key.spent_to_date > key.spending_limit:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": 1002,
                "detail": "Spending limit reached"
            }
        )

    try:
        await backend.perform_transaction(key, key.account, to_acc, data.amount)
    except:
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not perform transaction, please contact a developer"
        )
    else:
        return {"detail": "Successfully performed transaction"}

SORT_MODES = [0, 1] # 0 - newest first, 1 - oldest first
@app.get("/api/transactions")
async def get_transactions(key: Annotated[APIKey, Depends(get_typed_key(KeyType.GRANT))], limit: int = 25, sort: int = 0, before: Optional[float] = None, after: Optional[float] = None):
    # check parameters first
    if sort not in SORT_MODES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": 2000,
                "description": "Sort mode must be either: 0 - newest first, 1 - oldest first"
            }
        )
    elif limit <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": 2001,
                "description": "Limit must be greater than zero"
            }
        )
    elif limit > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": 2002,
                "description": "Can only fetch up to 100 transactions"
            }
        )

    assert(key.account)

    if not await backend.key_has_permission(key, Permissions.VIEW_BALANCE, account=key.account):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have the permission to view the transactions of this account"
        )

    actor = APIStubUser.from_key(key)
    transactions = await backend.get_transaction_log(actor, key.account, limit, True if sort == 1 else False, before, after)
    return [encode_transaction(t) for t in transactions]

async def run_api(bknd: Backend, bot: Optional[Client] = None, host: str = "127.0.0.1", port: int = 8000):
    global backend, client
    backend = bknd
    client = bot

    config = uvicorn.Config(app, host, port, log_level="warning", log_config=None)
    server = uvicorn.Server(config)

    await server.serve()

if __name__ == "__main__":
    async def main():
        global backend

        try:
            async with Backend("sqlite+aiosqlite:///database2.db") as backend:
                await run_api(backend)
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass