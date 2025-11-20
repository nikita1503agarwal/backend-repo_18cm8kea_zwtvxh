import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents
from schemas import User, Product, Category, Coupon, Cart, CartItem, Order, OrderItem, Address

# Optional: Stripe
STRIPE_SECRET = os.getenv("STRIPE_SECRET_KEY")
try:
    import stripe  # type: ignore
    if STRIPE_SECRET:
        stripe.api_key = STRIPE_SECRET
except Exception:  # pragma: no cover
    stripe = None

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("clickncart")

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret_change_me")
JWT_EXP_MIN = int(os.getenv("JWT_EXP_MIN", "60"))

# Configuration
STORE_NAME = os.getenv("STORE_NAME", "ClickNCart")
PRIMARY_CURRENCY = os.getenv("PRIMARY_CURRENCY", "USD")
DEFAULT_TAX_RATE = float(os.getenv("DEFAULT_TAX_RATE", "0.07"))  # 7%
SHIPPING_STANDARD = float(os.getenv("SHIPPING_STANDARD", "5.0"))
SHIPPING_EXPRESS = float(os.getenv("SHIPPING_EXPRESS", "15.0"))
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app = FastAPI(title="ClickNCart API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS] if ALLOWED_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities
class TokenData(BaseModel):
    user_id: str
    email: EmailStr
    role: str


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_token(user_doc: Dict[str, Any]) -> str:
    payload = {
        "sub": str(user_doc.get("_id")),
        "email": user_doc.get("email"),
        "role": user_doc.get("role", "customer"),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MIN),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return TokenData(user_id=payload["sub"], email=payload["email"], role=payload.get("role", "customer"))
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(authorization: Optional[str] = Header(default=None)) -> Optional[Dict[str, Any]]:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token_data = decode_token(token)
    user = db["user"].find_one({"_id": db.client.get_database().client.get_default_database().codec_options.document_class})  # type: ignore
    # The above is not practical to fetch; instead fetch by _id string using ObjectId
    from bson import ObjectId
    user = db["user"].find_one({"_id": ObjectId(token_data.user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_role(user: Dict[str, Any], roles: List[str]):
    if user.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")


# Error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# Health and config
@app.get("/")
def root():
    return {"name": STORE_NAME, "status": "ok"}


@app.get("/config")
def get_config():
    return {
        "storeName": STORE_NAME,
        "currency": PRIMARY_CURRENCY,
        "taxRate": DEFAULT_TAX_RATE,
        "shipping": {"standard": SHIPPING_STANDARD, "express": SHIPPING_EXPRESS},
        "payments": {"stripe": bool(STRIPE_SECRET)},
    }


# Auth
class RegisterDTO(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginDTO(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/register")
def register(data: RegisterDTO):
    existing = db["user"].find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already in use")
    password_hash = hash_password(data.password)
    user = User(name=data.name, email=data.email, password_hash=password_hash, role="customer")
    user_id = create_document("user", user)
    doc = db["user"].find_one({"_id": db.client.get_database().client.get_default_database().codec_options.document_class})  # placeholder to satisfy types
    from bson import ObjectId
    doc = db["user"].find_one({"_id": ObjectId(user_id)})
    token = create_token(doc)
    return {"token": token, "user": {"id": user_id, "name": doc["name"], "email": doc["email"], "role": doc.get("role", "customer")}}


@app.post("/auth/login")
def login(data: LoginDTO):
    user = db["user"].find_one({"email": data.email})
    if not user or not verify_password(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token, "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user.get("role", "customer")}}


@app.get("/auth/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user.get("role", "customer")}


# Categories
class CategoryDTO(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    parent_id: Optional[str] = None


@app.get("/categories")
def list_categories():
    cats = get_documents("category")
    for c in cats:
        c["id"] = str(c.pop("_id"))
    return cats


@app.post("/admin/categories")
def create_category(data: CategoryDTO, user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    require_role(user, ["admin", "staff"])
    cat = Category(**data.model_dump())
    cat_id = create_document("category", cat)
    return {"id": cat_id}


# Products
class ProductQuery(BaseModel):
    q: Optional[str] = None
    category: Optional[str] = None
    minPrice: Optional[float] = None
    maxPrice: Optional[float] = None
    sort: Optional[str] = None  # price_asc, price_desc, newest
    limit: int = 24
    page: int = 1


@app.get("/products")
def list_products(q: Optional[str] = None, category: Optional[str] = None, minPrice: Optional[float] = None,
                  maxPrice: Optional[float] = None, sort: Optional[str] = None, limit: int = 24, page: int = 1):
    query: Dict[str, Any] = {"active": True}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"tags": {"$regex": q, "$options": "i"}},
        ]
    if category:
        query["category_ids"] = category
    if minPrice is not None or maxPrice is not None:
        query["variants.price"] = {}
        if minPrice is not None:
            query["variants.price"]["$gte"] = float(minPrice)
        if maxPrice is not None:
            query["variants.price"]["$lte"] = float(maxPrice)
    cursor = db["product"].find(query)
    if sort == "price_asc":
        cursor = cursor.sort("variants.price", 1)
    elif sort == "price_desc":
        cursor = cursor.sort("variants.price", -1)
    elif sort == "newest":
        cursor = cursor.sort("created_at", -1)
    total = cursor.count() if hasattr(cursor, 'count') else db["product"].count_documents(query)
    cursor = cursor.skip((page - 1) * limit).limit(limit)
    items = []
    for p in cursor:
        p["id"] = str(p.pop("_id"))
        items.append(p)
    return {"items": items, "total": total, "page": page, "limit": limit}


@app.get("/products/{slug}")
def get_product(slug: str):
    p = db["product"].find_one({"slug": slug})
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    p["id"] = str(p.pop("_id"))
    return p


class ProductDTO(BaseModel):
    title: str
    slug: str
    description: Optional[str] = None
    category_ids: List[str] = []
    tags: List[str] = []
    images: List[str] = []
    variants: List[Dict[str, Any]] = []
    featured: bool = False
    active: bool = True


@app.post("/admin/products")
def create_product(data: ProductDTO, user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    require_role(user, ["admin", "staff"])
    prod = Product(**data.model_dump())
    prod_id = create_document("product", prod)
    return {"id": prod_id}


@app.put("/admin/products/{product_id}")
def update_product(product_id: str, data: ProductDTO, user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    require_role(user, ["admin", "staff"])
    from bson import ObjectId
    db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": data.model_dump() | {"updated_at": datetime.now(timezone.utc)}})
    return {"id": product_id, "updated": True}


@app.delete("/admin/products/{product_id}")
def delete_product(product_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    require_role(user, ["admin", "staff"])
    from bson import ObjectId
    db["product"].delete_one({"_id": ObjectId(product_id)})
    return {"id": product_id, "deleted": True}


# Coupons
class CouponApplyDTO(BaseModel):
    code: str
    subtotal: float


@app.post("/coupons/apply")
def apply_coupon(data: CouponApplyDTO):
    coup = db["coupon"].find_one({"code": data.code, "active": True})
    if not coup:
        raise HTTPException(status_code=404, detail="Invalid coupon")
    if coup.get("expires_at") and coup["expires_at"] < datetime.now(timezone.utc).isoformat():
        raise HTTPException(status_code=400, detail="Coupon expired")
    discount = 0.0
    if coup.get("type") == "percent":
        discount = round(data.subtotal * float(coup.get("value", 0)) / 100.0, 2)
    else:
        discount = float(coup.get("value", 0))
    return {"code": coup["code"], "discount": discount}


# Cart
class CartKeyDTO(BaseModel):
    cart_key: Optional[str] = None


def compute_totals(items: List[CartItem], shipping_method: str = "standard", coupon_code: Optional[str] = None):
    subtotal = round(sum(i.price * i.quantity for i in items), 2)
    shipping = SHIPPING_STANDARD if shipping_method == "standard" else SHIPPING_EXPRESS
    discount = 0.0
    if coupon_code:
        res = apply_coupon(CouponApplyDTO(code=coupon_code, subtotal=subtotal))
        discount = res["discount"]
    taxable_amount = max(subtotal - discount, 0)
    tax = round(taxable_amount * DEFAULT_TAX_RATE, 2)
    total = round(taxable_amount + shipping + tax, 2)
    return {"subtotal": subtotal, "discount": discount, "shipping": shipping, "tax": tax, "total": total}


@app.post("/cart/add")
def cart_add(item: CartItem, key: CartKeyDTO = Depends()):
    # Resolve cart by user or key
    cart_filter: Dict[str, Any] = {}
    if key.cart_key:
        cart_filter["cart_key"] = key.cart_key
    cart = db["cart"].find_one(cart_filter) if cart_filter else None
    if not cart:
        cart = Cart(cart_key=key.cart_key, items=[item]).model_dump()
        cid = create_document("cart", cart)
        return {"cart_id": cid}
    else:
        # merge if same product+variant
        merged = False
        for it in cart.get("items", []):
            if it.get("product_id") == item.product_id and it.get("variant_sku") == item.variant_sku:
                it["quantity"] += item.quantity
                merged = True
                break
        if not merged:
            cart["items"].append(item.model_dump())
        db["cart"].update_one({"_id": cart["_id"]}, {"$set": {"items": cart["items"], "updated_at": datetime.now(timezone.utc)}})
        return {"cart_id": str(cart["_id"]) }


@app.get("/cart")
def cart_get(cart_key: str):
    cart = db["cart"].find_one({"cart_key": cart_key})
    if not cart:
        return {"items": [], "totals": compute_totals([])}
    items = [CartItem(**i) for i in cart.get("items", [])]
    totals = compute_totals(items, coupon_code=cart.get("coupon_code"))
    cart["id"] = str(cart.pop("_id"))
    cart["totals"] = totals
    return cart


class CartUpdateDTO(BaseModel):
    cart_key: str
    items: List[CartItem]
    coupon_code: Optional[str] = None


@app.post("/cart/update")
def cart_update(data: CartUpdateDTO):
    cart = db["cart"].find_one({"cart_key": data.cart_key})
    payload = data.model_dump()
    if not cart:
        create_document("cart", payload)
    else:
        db["cart"].update_one({"_id": cart["_id"]}, {"$set": payload | {"updated_at": datetime.now(timezone.utc)}})
    items = [CartItem(**i) for i in data.items]
    return {"ok": True, "totals": compute_totals(items, coupon_code=data.coupon_code)}


# Checkout
class CheckoutDTO(BaseModel):
    cart_key: str
    email: EmailStr
    shipping_address: Address
    billing_address: Optional[Address] = None
    shipping_method: str = "standard"
    coupon_code: Optional[str] = None
    payment_provider: str = "dummy"  # dummy | stripe


@app.post("/checkout")
def checkout(data: CheckoutDTO):
    cart = db["cart"].find_one({"cart_key": data.cart_key})
    if not cart or not cart.get("items"):
        raise HTTPException(status_code=400, detail="Cart is empty")
    items = [CartItem(**i) for i in cart.get("items", [])]
    totals = compute_totals(items, shipping_method=data.shipping_method, coupon_code=data.coupon_code)
    order_items = [OrderItem(product_id=i.product_id, title=i.title, variant_sku=i.variant_sku,
                             quantity=i.quantity, unit_price=i.price, image=i.image, options=i.options) for i in items]
    order = Order(
        user_id=cart.get("user_id"),
        email=data.email,
        items=order_items,
        subtotal=totals["subtotal"],
        discount=totals["discount"],
        shipping=totals["shipping"],
        tax=totals["tax"],
        total=totals["total"],
        currency=PRIMARY_CURRENCY,
        shipping_address=data.shipping_address,
        billing_address=data.billing_address or data.shipping_address,
        status="pending",
        payment_status="unpaid",
        payment_provider=data.payment_provider,
    )
    order_id = create_document("order", order)

    client_secret = None
    if data.payment_provider == "stripe":
        if not stripe or not STRIPE_SECRET:
            raise HTTPException(status_code=400, detail="Stripe not configured")
        intent = stripe.PaymentIntent.create(amount=int(order.total * 100), currency=PRIMARY_CURRENCY.lower(), metadata={"order_id": order_id})
        client_secret = intent.client_secret
    elif data.payment_provider == "dummy":
        # Immediately mark as paid for dummy
        from bson import ObjectId
        db["order"].update_one({"_id": ObjectId(order_id)}, {"$set": {"payment_status": "paid", "status": "paid"}})

    # clear cart after checkout
    db["cart"].delete_one({"cart_key": data.cart_key})

    return {"order_id": order_id, "total": order.total, "client_secret": client_secret}


# Orders
@app.get("/orders")
def list_orders(user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    cursor = db["order"].find({"email": user.get("email")}) if user.get("role") == "customer" else db["order"].find({})
    items = []
    for o in cursor.sort("created_at", -1).limit(100):
        o["id"] = str(o.pop("_id"))
        items.append(o)
    return items


@app.get("/orders/{order_id}")
def get_order(order_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from bson import ObjectId
    o = db["order"].find_one({"_id": ObjectId(order_id)})
    if not o:
        raise HTTPException(status_code=404, detail="Not found")
    if user.get("role") == "customer" and o.get("email") != user.get("email"):
        raise HTTPException(status_code=403, detail="Forbidden")
    o["id"] = str(o.pop("_id"))
    return o


class OrderStatusDTO(BaseModel):
    status: str
    payment_status: Optional[str] = None


@app.post("/admin/orders/{order_id}/status")
def update_order_status(order_id: str, data: OrderStatusDTO, user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    require_role(user, ["admin", "staff"])
    from bson import ObjectId
    update = {"status": data.status}
    if data.payment_status:
        update["payment_status"] = data.payment_status
    db["order"].update_one({"_id": ObjectId(order_id)}, {"$set": update | {"updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}


# Admin analytics
@app.get("/admin/analytics")
def analytics(user: Dict[str, Any] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    require_role(user, ["admin", "staff"])
    total_orders = db["order"].count_documents({})
    revenue = 0.0
    for o in db["order"].find({"payment_status": "paid"}):
        revenue += float(o.get("total", 0))
    top_products = []
    return {"revenue": round(revenue, 2), "orders": total_orders, "topProducts": top_products}


# Stripe webhook (optional)
@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    if not stripe:
        return {"ok": True}
    payload = await request.body()
    sig = request.headers.get("Stripe-Signature")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    event = None
    try:
        if endpoint_secret:
            event = stripe.Webhook.construct_event(payload, sig, endpoint_secret)
        else:
            event = stripe.Event.construct_from(await request.json(), stripe.api_key)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid payload"})

    if event and event["type"] == "payment_intent.succeeded":
        intent = event["data"]["object"]
        order_id = intent.get("metadata", {}).get("order_id")
        if order_id:
            from bson import ObjectId
            db["order"].update_one({"_id": ObjectId(order_id)}, {"$set": {"payment_status": "paid", "status": "paid"}})
    return {"received": True}


# Sample seed endpoint (dev only)
@app.post("/dev/seed")
def seed():
    # Create admin if not exists
    if not db["user"].find_one({"email": "admin@clickncart.store"}):
        admin = User(name="Admin", email="admin@clickncart.store", password_hash=hash_password("admin123"), role="admin")
        create_document("user", admin)
    # Create categories and a few products if empty
    if db["category"].count_documents({}) == 0:
        cat_id = create_document("category", Category(name="Apparel", slug="apparel", description="Clothing").model_dump())
        cat2_id = create_document("category", Category(name="Electronics", slug="electronics").model_dump())
        # Products
        p1 = Product(
            title="Classic Tee",
            slug="classic-tee",
            description="Soft cotton tee",
            category_ids=[cat_id],
            tags=["shirt", "cotton"],
            images=["https://images.unsplash.com/photo-1520975682031-a1248f1a6386"],
            variants=[{"sku": "TEE-CLSC-S", "options": {"size": "S", "color": "Black"}, "price": 20.0, "stock": 100},
                     {"sku": "TEE-CLSC-M", "options": {"size": "M", "color": "Black"}, "price": 20.0, "stock": 100}],
            featured=True,
        )
        create_document("product", p1)
        p2 = Product(
            title="Wireless Earbuds",
            slug="wireless-earbuds",
            description="Noise isolating, long battery life",
            category_ids=[cat2_id],
            tags=["audio", "bluetooth"],
            images=["https://images.unsplash.com/photo-1585386959984-a41552231620"],
            variants=[{"sku": "EAR-WLS-WHT", "options": {"color": "White"}, "price": 59.99, "stock": 50}],
            featured=True,
        )
        create_document("product", p2)
    if db["coupon"].count_documents({}) == 0:
        create_document("coupon", Coupon(code="WELCOME10", type="percent", value=10).model_dump())
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
