from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import bcrypt
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'inventory_db')]

# JWT Secret
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ============== MODELS ==============

class UserRole(str):
    ADMIN = "Admin"
    WAREHOUSE_STAFF = "Warehouse Staff"

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str  # Admin or Warehouse Staff

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: str
    role: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str

class TokenResponse(BaseModel):
    token: str
    user: UserResponse

class ProductCreate(BaseModel):
    name: str
    sku: str

class Product(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    sku: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class InventoryTransaction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    product_id: str
    product_name: str
    transaction_type: str  # "in" or "out"
    quantity: int
    processed_by: str  # user name
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanRequest(BaseModel):
    product_id: str
    quantity: int = 1

class StockInfo(BaseModel):
    product_id: str
    product_name: str
    sku: str
    current_stock: int

# ============== AUTH HELPERS ==============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {"user_id": user_id, "email": email, "role": role}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============== AUTH ROUTES ==============

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Validate role
    if user_data.role not in ["Admin", "Warehouse Staff"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    # Create user
    hashed_pw = hash_password(user_data.password)
    user = User(
        name=user_data.name,
        email=user_data.email,
        role=user_data.role
    )
    
    user_dict = user.model_dump()
    user_dict['password'] = hashed_pw
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    
    await db.users.insert_one(user_dict)
    
    token = create_token(user.id, user.email, user.role)
    return TokenResponse(
        token=token,
        user=UserResponse(id=user.id, name=user.name, email=user.email, role=user.role)
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user['id'], user['email'], user['role'])
    return TokenResponse(
        token=token,
        user=UserResponse(id=user['id'], name=user['name'], email=user['email'], role=user['role'])
    )

# ============== PRODUCT ROUTES ==============

@api_router.post("/products", response_model=Product)
async def create_product(product_data: ProductCreate, current_user: dict = Depends(get_current_user)):
    # Only admins can create products
    if current_user['role'] != "Admin":
        raise HTTPException(status_code=403, detail="Only admins can create products")
    
    # Check if SKU exists
    existing = await db.products.find_one({"sku": product_data.sku}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="SKU already exists")
    
    product = Product(name=product_data.name, sku=product_data.sku)
    product_dict = product.model_dump()
    product_dict['created_at'] = product_dict['created_at'].isoformat()
    
    await db.products.insert_one(product_dict)
    return product

@api_router.get("/products", response_model=List[Product])
async def get_products(current_user: dict = Depends(get_current_user)):
    products = await db.products.find({}, {"_id": 0}).to_list(1000)
    for p in products:
        if isinstance(p['created_at'], str):
            p['created_at'] = datetime.fromisoformat(p['created_at'])
    return products

@api_router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str, current_user: dict = Depends(get_current_user)):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    if isinstance(product['created_at'], str):
        product['created_at'] = datetime.fromisoformat(product['created_at'])
    return product

# ============== INVENTORY ROUTES ==============

@api_router.post("/inventory/scan-in")
async def scan_in(scan_data: ScanRequest, current_user: dict = Depends(get_current_user)):
    # Get product
    product = await db.products.find_one({"id": scan_data.product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Create transaction
    transaction = InventoryTransaction(
        product_id=scan_data.product_id,
        product_name=product['name'],
        transaction_type="in",
        quantity=scan_data.quantity,
        processed_by=current_user['name']
    )
    
    trans_dict = transaction.model_dump()
    trans_dict['timestamp'] = trans_dict['timestamp'].isoformat()
    await db.transactions.insert_one(trans_dict)
    
    return {"message": "Stock added successfully", "transaction": transaction}

@api_router.post("/inventory/scan-out")
async def scan_out(scan_data: ScanRequest, current_user: dict = Depends(get_current_user)):
    # Get product
    product = await db.products.find_one({"id": scan_data.product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Check current stock
    current_stock = await get_current_stock_for_product(scan_data.product_id)
    if current_stock < scan_data.quantity:
        raise HTTPException(status_code=400, detail=f"Insufficient stock. Available: {current_stock}")
    
    # Create transaction
    transaction = InventoryTransaction(
        product_id=scan_data.product_id,
        product_name=product['name'],
        transaction_type="out",
        quantity=scan_data.quantity,
        processed_by=current_user['name']
    )
    
    trans_dict = transaction.model_dump()
    trans_dict['timestamp'] = trans_dict['timestamp'].isoformat()
    await db.transactions.insert_one(trans_dict)
    
    return {"message": "Stock removed successfully", "transaction": transaction}

@api_router.get("/inventory/history", response_model=List[InventoryTransaction])
async def get_history(current_user: dict = Depends(get_current_user)):
    transactions = await db.transactions.find({}, {"_id": 0}).sort("timestamp", -1).to_list(1000)
    for t in transactions:
        if isinstance(t['timestamp'], str):
            t['timestamp'] = datetime.fromisoformat(t['timestamp'])
    return transactions

@api_router.get("/inventory/stock", response_model=List[StockInfo])
async def get_stock(current_user: dict = Depends(get_current_user)):
    products = await db.products.find({}, {"_id": 0}).to_list(1000)
    stock_info = []
    
    for product in products:
        current_stock = await get_current_stock_for_product(product['id'])
        stock_info.append(StockInfo(
            product_id=product['id'],
            product_name=product['name'],
            sku=product['sku'],
            current_stock=current_stock
        ))
    
    return stock_info

async def get_current_stock_for_product(product_id: str) -> int:
    transactions = await db.transactions.find({"product_id": product_id}, {"_id": 0}).to_list(10000)
    stock = 0
    for t in transactions:
        if t['transaction_type'] == "in":
            stock += t['quantity']
        else:
            stock -= t['quantity']
    return stock

# ============== ROOT ROUTE ==============

@api_router.get("/")
async def root():
    return {"message": "Inventory Management API"}

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

