from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional

# ==========================================
# 1. KONFIGURASI DATABASE (SQLite & SQLAlchemy)
# ==========================================
SQLALCHEMY_DATABASE_URL = "sqlite:///./lintaskota.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# 2. KONFIGURASI KEAMANAN (JWT & Password Hashing)
# ==========================================
# Catatan: Di tahap produksi, SECRET_KEY harus diletakkan di file .env
SECRET_KEY = "rahasia_lintaskota_super_aman"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Fungsi utilitas keamanan
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 3. MODEL DATABASE (ORM SQLAlchemy)
# ==========================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="passenger") # passenger, driver
    
    # Relasi ke bookings
    bookings = relationship("Booking", back_populates="owner")

class TravelRoute(Base):
    __tablename__ = "travel_routes"
    id = Column(Integer, primary_key=True, index=True)
    destination = Column(String, index=True) # Contoh: "Makassar - Palopo"
    departure_time = Column(DateTime)
    price = Column(Integer)
    total_seats = Column(Integer)
    vehicle_type = Column(String) # "Travel Resmi" atau "Mobil Pribadi"
    
    # Relasi ke bookings (One to Many)
    bookings = relationship("Booking", back_populates="route")

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    route_id = Column(Integer, ForeignKey("travel_routes.id"))
    seats_reserved = Column(Integer)
    
    # Relasi balik
    owner = relationship("User", back_populates="bookings")
    route = relationship("TravelRoute", back_populates="bookings")

# Buat tabel di database
Base.metadata.create_all(bind=engine)

# ==========================================
# 4. SKEMA VALIDASI (Pydantic)
# ==========================================
class UserCreate(BaseModel):
    email: str
    password: str

class RouteCreate(BaseModel):
    destination: str
    departure_time: datetime
    price: int
    total_seats: int
    vehicle_type: str

class RouteResponse(RouteCreate):
    id: int
    class Config:
        from_attributes = True

class BookingCreate(BaseModel):
    route_id: int
    seats_reserved: int

# ==========================================
# 5. DEPENDENCIES
# ==========================================
# Dependency untuk mendapatkan sesi database (seperti pelayan mengambilkan data)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency untuk mendapatkan user yang sedang login dari token JWT
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token tidak valid atau sudah kedaluwarsa",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# ==========================================
# 6. INISIALISASI FASTAPI & ROUTES
# ==========================================
app = FastAPI(
    title="LintasKota API",
    description="API Reservasi Travel & Carpooling Antarkota",
    version="1.0.0"
)

# Endpoint: Registrasi User Baru
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email sudah terdaftar")
    
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Registrasi berhasil", "email": new_user.email}

# Endpoint: Login untuk mendapatkan Token (JWT)
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email atau password salah",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoint: Tambah Rute Travel (Bisa diakses publik untuk testing saat ini)
@app.post("/routes", response_model=RouteResponse, status_code=status.HTTP_201_CREATED)
def create_route(route: RouteCreate, db: Session = Depends(get_db)):
    new_route = TravelRoute(**route.dict())
    db.add(new_route)
    db.commit()
    db.refresh(new_route)
    return new_route

# Endpoint: Lihat Semua Rute Travel (Metode GET)
@app.get("/routes", response_model=List[RouteResponse])
def get_all_routes(db: Session = Depends(get_db)):
    # Mengambil semua rute travel dari database
    routes = db.query(TravelRoute).all()
    return routes

# Endpoint: Booking Kursi (Hanya bisa diakses jika sudah login/punya Token)
@app.post("/bookings", status_code=status.HTTP_201_CREATED)
def create_booking(booking: BookingCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # 1. Cek apakah rute ada
    route = db.query(TravelRoute).filter(TravelRoute.id == booking.route_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Rute travel tidak ditemukan")
    
    # 2. Validasi kapasitas (contoh sederhana)
    # Di aplikasi nyata, kita harus menghitung total kursi yang sudah dipesan dulu
    if booking.seats_reserved > route.total_seats:
        raise HTTPException(status_code=400, detail="Kursi tidak mencukupi")
        
    # 3. Buat pesanan baru
    new_booking = Booking(
        user_id=current_user.id,
        route_id=route.id,
        seats_reserved=booking.seats_reserved
    )
    db.add(new_booking)
    db.commit()
    return {"message": "Booking berhasil dibuat", "route": route.destination, "seats": booking.seats_reserved}