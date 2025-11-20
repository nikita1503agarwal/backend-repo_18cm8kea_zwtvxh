"""
ClickNCart Database Schemas

Each Pydantic model below represents one MongoDB collection. The collection name is the lowercase
class name. Example: class User -> collection "user".

These schemas are used for validation before inserting/updating documents.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr


class Address(BaseModel):
    full_name: str
    line1: str
    line2: Optional[str] = None
    city: str
    state: str
    postal_code: str
    country: str = "US"
    phone: Optional[str] = None


class User(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    role: str = Field("customer", description="customer | staff | admin")
    is_active: bool = True
    addresses: List[Address] = []


class Category(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    parent_id: Optional[str] = None


class ProductVariant(BaseModel):
    sku: str
    options: Dict[str, str] = Field(default_factory=dict, description="e.g., {'size':'M','color':'Red'}")
    price: float
    compare_at_price: Optional[float] = None
    stock: int = 0


class Product(BaseModel):
    title: str
    slug: str
    description: Optional[str] = None
    category_ids: List[str] = []
    tags: List[str] = []
    images: List[str] = []
    variants: List[ProductVariant] = []
    featured: bool = False
    active: bool = True


class Coupon(BaseModel):
    code: str
    type: str = Field("percent", description="percent|flat")
    value: float = Field(..., ge=0)
    expires_at: Optional[str] = None  # ISO date string
    usage_limit: Optional[int] = None
    used_count: int = 0
    active: bool = True


class CartItem(BaseModel):
    product_id: str
    variant_sku: Optional[str] = None
    quantity: int = Field(1, ge=1)
    price: float  # captured price at add-to-cart time
    title: str
    image: Optional[str] = None
    options: Dict[str, str] = {}


class Cart(BaseModel):
    user_id: Optional[str] = None
    cart_key: Optional[str] = None  # for guests
    items: List[CartItem] = []
    coupon_code: Optional[str] = None


class OrderItem(BaseModel):
    product_id: str
    title: str
    variant_sku: Optional[str] = None
    quantity: int
    unit_price: float
    image: Optional[str] = None
    options: Dict[str, str] = {}


class Order(BaseModel):
    user_id: Optional[str] = None
    email: EmailStr
    items: List[OrderItem]
    subtotal: float
    discount: float = 0.0
    shipping: float = 0.0
    tax: float = 0.0
    total: float
    currency: str = "USD"
    shipping_address: Address
    billing_address: Optional[Address] = None
    status: str = Field("pending", description="pending|paid|shipped|delivered|cancelled|refunded")
    payment_status: str = Field("unpaid", description="unpaid|paid|refunded|failed")
    payment_provider: Optional[str] = None
    payment_ref: Optional[str] = None

