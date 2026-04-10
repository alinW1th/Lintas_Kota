import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr, field_validator
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional

# ============================================================
# 1. LOAD ENVIRONMENT VARIABLES
# ============================================================
load_dotenv()

DATABASE_URL              = os.getenv("DATABASE_URL", "sqlite:///./lintaskota.db")
SECRET_KEY                = os.getenv("SECRET_KEY", "fallback_secret_key")
ALGORITHM                 = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
APP_NAME                  = os.getenv("APP_NAME", "LintasKota API")
APP_VERSION               = os.getenv("APP_VERSION", "1.0.0")
APP_DESCRIPTION           = os.getenv("APP_DESCRIPTION", "API Reservasi Travel & Carpooling Antarkota")
DEBUG                     = os.getenv("DEBUG", "False").lower() == "true"
ALLOWED_ORIGINS           = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

# ============================================================
# 2. KONFIGURASI DATABASE
# ============================================================
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ============================================================
# 3. MODEL DATABASE (ORM SQLAlchemy)
# ============================================================
class User(Base):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    name            = Column(String, nullable=False)
    email           = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role            = Column(String, default="passenger")  # passenger | driver | admin
    phone           = Column(String, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    bookings = relationship("Booking", back_populates="owner", cascade="all, delete-orphan")


class TravelRoute(Base):
    __tablename__ = "travel_routes"

    id             = Column(Integer, primary_key=True, index=True)
    destination    = Column(String, index=True, nullable=False)
    departure_time = Column(DateTime, nullable=False)
    price          = Column(Integer, nullable=False)
    total_seats    = Column(Integer, nullable=False)
    vehicle_type   = Column(String, nullable=False)  # Travel Resmi | Mobil Pribadi
    created_at     = Column(DateTime, default=datetime.utcnow)
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    bookings = relationship("Booking", back_populates="route", cascade="all, delete-orphan")


class Booking(Base):
    __tablename__ = "bookings"

    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=False)
    route_id       = Column(Integer, ForeignKey("travel_routes.id"), nullable=False)
    seats_reserved = Column(Integer, nullable=False)
    status         = Column(String, default="confirmed")  # confirmed | cancelled
    created_at     = Column(DateTime, default=datetime.utcnow)
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="bookings")
    route = relationship("TravelRoute", back_populates="bookings")


# Buat semua tabel jika belum ada
Base.metadata.create_all(bind=engine)

# ============================================================
# 4. SKEMA PYDANTIC (Request & Response)
# ============================================================

# ---------- AUTH ----------
class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    phone: Optional[str] = None
    role: Optional[str] = "passenger"

class UserUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    role: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    phone: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# ---------- ROUTES ----------
class RouteCreate(BaseModel):
    destination: str
    departure_time: datetime
    price: int
    total_seats: int
    vehicle_type: str

class RouteUpdate(BaseModel):
    destination: Optional[str] = None
    departure_time: Optional[datetime] = None
    price: Optional[int] = None
    total_seats: Optional[int] = None
    vehicle_type: Optional[str] = None

class RouteResponse(BaseModel):
    id: int
    destination: str
    departure_time: datetime
    price: int
    total_seats: int
    vehicle_type: str
    created_at: datetime

    class Config:
        from_attributes = True

# ---------- BOOKINGS ----------
class BookingCreate(BaseModel):
    route_id: int
    seats_reserved: int

class BookingUpdate(BaseModel):
    seats_reserved: Optional[int] = None
    status: Optional[str] = None

class BookingResponse(BaseModel):
    id: int
    user_id: int
    route_id: int
    seats_reserved: int
    status: str
    created_at: datetime
    route: Optional[RouteResponse] = None

    class Config:
        from_attributes = True

# ============================================================
# 5. UTILITAS KEAMANAN
# ============================================================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ============================================================
# 6. DEPENDENCIES
# ============================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token tidak valid atau sudah kedaluwarsa",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise exc
    except JWTError:
        raise exc
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise exc
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang bisa mengakses ini")
    return current_user

# ============================================================
# 7. INISIALISASI FASTAPI & MIDDLEWARE
# ============================================================
app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount folder static (CSS, JS, gambar jika ada)
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception:
    pass  # skip jika folder static tidak tersedia (misal di Vercel)

# ============================================================
# 8. ENDPOINTS - AUTH
# ============================================================

@app.get("/", response_class=HTMLResponse, tags=["Root"])
def root():
    """Landing page LintasKota API."""
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        return HTMLResponse(content="<h1>LintasKota API</h1><p>Docs: <a href='/docs'>/docs</a></p>")


@app.post("/register", response_model=UserResponse, status_code=201, tags=["Auth"])
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Registrasi akun pengguna baru."""
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email sudah terdaftar")
    new_user = User(
        name=user.name,
        email=user.email,
        hashed_password=get_password_hash(user.password),
        phone=user.phone,
        role=user.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/login", response_model=Token, tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login dengan email (isi di field username) & password, dapatkan JWT token."""
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email atau password salah",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me", response_model=UserResponse, tags=["Auth"])
def me(current_user: User = Depends(get_current_user)):
    """Lihat profil akun yang sedang login."""
    return current_user

# ============================================================
# 9. ENDPOINTS - USERS (CRUD - admin only)
# ============================================================

@app.get("/users", response_model=List[UserResponse], tags=["Users"])
def list_users(
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """[Admin] Lihat semua pengguna."""
    return db.query(User).offset(skip).limit(limit).all()


@app.get("/users/{user_id}", response_model=UserResponse, tags=["Users"])
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """[Admin] Lihat detail pengguna berdasarkan ID."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Pengguna tidak ditemukan")
    return user


@app.put("/users/{user_id}", response_model=UserResponse, tags=["Users"])
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update data pengguna. Admin bisa update siapa saja; user biasa hanya bisa update dirinya sendiri."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Pengguna tidak ditemukan")
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Tidak punya izin untuk mengubah data ini")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(user, field, value)
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user


@app.delete("/users/{user_id}", status_code=204, tags=["Users"])
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """[Admin] Hapus pengguna berdasarkan ID."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Pengguna tidak ditemukan")
    db.delete(user)
    db.commit()

# ============================================================
# 10. ENDPOINTS - TRAVEL ROUTES (CRUD)
# ============================================================

@app.get("/routes", response_model=List[RouteResponse], tags=["Routes"])
def list_routes(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    """Lihat semua rute travel (publik)."""
    return db.query(TravelRoute).offset(skip).limit(limit).all()


@app.get("/routes/{route_id}", response_model=RouteResponse, tags=["Routes"])
def get_route(route_id: int, db: Session = Depends(get_db)):
    """Lihat detail satu rute travel berdasarkan ID (publik)."""
    route = db.query(TravelRoute).filter(TravelRoute.id == route_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Rute tidak ditemukan")
    return route


@app.post("/routes", response_model=RouteResponse, status_code=201, tags=["Routes"])
def create_route(
    route: RouteCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """[Admin] Tambah rute travel baru."""
    new_route = TravelRoute(**route.model_dump())
    db.add(new_route)
    db.commit()
    db.refresh(new_route)
    return new_route


@app.put("/routes/{route_id}", response_model=RouteResponse, tags=["Routes"])
def update_route(
    route_id: int,
    payload: RouteUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """[Admin] Update data rute travel."""
    route = db.query(TravelRoute).filter(TravelRoute.id == route_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Rute tidak ditemukan")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(route, field, value)
    route.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(route)
    return route


@app.delete("/routes/{route_id}", status_code=204, tags=["Routes"])
def delete_route(
    route_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """[Admin] Hapus rute travel. Semua booking terkait juga akan terhapus (cascade)."""
    route = db.query(TravelRoute).filter(TravelRoute.id == route_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Rute tidak ditemukan")
    db.delete(route)
    db.commit()

# ============================================================
# 11. ENDPOINTS - BOOKINGS (CRUD)
# ============================================================

@app.get("/bookings", response_model=List[BookingResponse], tags=["Bookings"])
def list_bookings(
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lihat semua booking. Admin melihat semua; pengguna hanya melihat miliknya sendiri."""
    if current_user.role == "admin":
        return db.query(Booking).offset(skip).limit(limit).all()
    return db.query(Booking).filter(Booking.user_id == current_user.id).offset(skip).limit(limit).all()


@app.get("/bookings/{booking_id}", response_model=BookingResponse, tags=["Bookings"])
def get_booking(
    booking_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lihat detail booking berdasarkan ID."""
    booking = db.query(Booking).filter(Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking tidak ditemukan")
    if current_user.role != "admin" and booking.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Tidak punya izin untuk melihat booking ini")
    return booking


@app.post("/bookings", response_model=BookingResponse, status_code=201, tags=["Bookings"])
def create_booking(
    booking: BookingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Buat booking kursi untuk rute travel tertentu."""
    route = db.query(TravelRoute).filter(TravelRoute.id == booking.route_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Rute travel tidak ditemukan")

    # Hitung kursi yang sudah dipesan (hanya yang masih confirmed)
    booked = db.query(func.sum(Booking.seats_reserved)).filter(
        Booking.route_id == booking.route_id,
        Booking.status == "confirmed",
    ).scalar() or 0

    available = route.total_seats - booked
    if booking.seats_reserved > available:
        raise HTTPException(
            status_code=400,
            detail=f"Kursi tidak mencukupi. Tersedia: {available} kursi",
        )

    new_booking = Booking(
        user_id=current_user.id,
        route_id=route.id,
        seats_reserved=booking.seats_reserved,
    )
    db.add(new_booking)
    db.commit()
    db.refresh(new_booking)
    return new_booking


@app.put("/bookings/{booking_id}", response_model=BookingResponse, tags=["Bookings"])
def update_booking(
    booking_id: int,
    payload: BookingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update booking (ubah jumlah kursi atau batalkan). Hanya pemilik / admin."""
    booking = db.query(Booking).filter(Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking tidak ditemukan")
    if current_user.role != "admin" and booking.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Tidak punya izin untuk mengubah booking ini")

    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(booking, field, value)
    booking.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(booking)
    return booking


@app.delete("/bookings/{booking_id}", status_code=204, tags=["Bookings"])
def delete_booking(
    booking_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Hapus / batalkan booking. Hanya pemilik / admin."""
    booking = db.query(Booking).filter(Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking tidak ditemukan")
    if current_user.role != "admin" and booking.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Tidak punya izin untuk menghapus booking ini")
    db.delete(booking)
    db.commit()