from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, ConfigDict, validator
from sqlalchemy import create_engine, Column, Integer, String, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from passlib.context import CryptContext
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import csv
import io

from fastapi_ldap import LDAPAuth, LDAPSettings, require_groups
import config

settings = LDAPSettings(
    ldap_url=config.LDAP_CONFIG['ldap_url'],
    ldap_base_dn=config.LDAP_CONFIG['ldap_base_dn'],
    bind_dn=config.LDAP_CONFIG['bind_dn'],
    bind_password=config.LDAP_CONFIG['bind_password'],
    use_tls=config.LDAP_CONFIG['use_tls'],
    user_search_filter=config.LDAP_CONFIG['user_search_filter'],
)

# Create LDAP auth instance
ldap_auth = LDAPAuth(settings)

# FastAPI app
app = FastAPI(
    title="Researchers API",
    version="1.0.0",
    description="Researchers Management API with JWT Authentication",
    lifespan=ldap_auth.lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Database setup
SQLALCHEMY_DATABASE_URL = config.SQLALCHEMY_DATABASE_URL
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security
SECRET_KEY = "122233mkdsjadkasdk"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 2
security = HTTPBearer()
pwd_context = CryptContext(schemes=["argon2", "bcrypt", "scrypt"], deprecated="auto")

#
# Database models
#
class Faculty(Base):
    __tablename__ = "faculty"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False, index=True)    
    departments = relationship("Department", back_populates="faculty")

class Department(Base):
    __tablename__ = "department"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)    
    faculty_id = Column(Integer, ForeignKey("faculty.id", ondelete="CASCADE"), nullable=False)
    faculty = relationship("Faculty", back_populates="departments")
    customers = relationship("Customer", back_populates="department")

# Customer model contains relationships to Faculty and Department
class Customer(Base):
    __tablename__ = "customer"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    orcid = Column(String(255), nullable=True)
    scopusid = Column(String(255), nullable=True)
    ecrisid = Column(String(255), nullable=True)
    
    # Foreign keys
    faculty_id = Column(Integer, ForeignKey("faculty.id"), nullable=True)  # Optional for now
    department_id = Column(Integer, ForeignKey("department.id"), nullable=True)  # Optional for now
    
    # Relationships
    faculty = relationship("Faculty")
    department = relationship("Department")

class User(Base):
    __tablename__ = "user"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)


# Create tables
Base.metadata.create_all(bind=engine)

#
# Pydantic schemas
#
class FacultyBase(BaseModel):
    name: str = Field(..., max_length=255)

class FacultyResponse(FacultyBase):
    id: int
    model_config = ConfigDict(from_attributes=True)

class DepartmentBase(BaseModel):
    name: str = Field(..., max_length=255)
    faculty_id: int

class DepartmentResponse(DepartmentBase):
    id: int
    model_config = ConfigDict(from_attributes=True)

class CustomerBase(BaseModel):
    name: str = Field(..., max_length=255, description="Customer name")
    email: str = Field(..., max_length=255, description="Customer email")
    orcid: Optional[str] = Field(None, max_length=20, description="ORCID identifier")
    scopusid: Optional[str] = Field(None, max_length=20, description="Scopus ID")
    ecrisid: Optional[str] = Field(None, max_length=20, description="ECRIS ID")
    faculty_id: Optional[int] = None
    department_id: Optional[int] = None

class CustomerCreate(CustomerBase):
    pass

class CustomerUpdate(CustomerBase):
    pass

class CustomerResponse(CustomerBase):
    id: int
    #faculty: Optional[FacultyResponse] = None
    #department: Optional[DepartmentResponse] = None
    faculty_id: Optional[int] = None
    department_id: Optional[int] = None
    model_config = ConfigDict(from_attributes=True)

#
# Wrapper models for consistent responses
#
class CustomerDataResponse(BaseModel):
    status: bool
    message: str
    data: CustomerResponse

class CustomersListDataResponse(BaseModel):
    status: bool
    message: str
    data: List[CustomerResponse]
    paging: dict

class ErrorResponse(BaseModel):
    status: bool
    message: str
    errors: Optional[dict] = None

class LoginSchema(BaseModel):
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password")

class RegisterSchema(BaseModel):
    email: str = Field(..., description="User email")
    password: str = Field(..., min_length=6, description="User password (min 6 chars)")

class TokenResponse(BaseModel):
    status: bool
    message: str
    data: dict

class ProfileResponse(BaseModel):
    status: bool
    message: str
    data: dict

class TokenData(BaseModel):
    id: Optional[int]
    username: Optional[str]
    email: Optional[str]

#
# Dependency to get database session
#
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

#
# Helper functions
#
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        print(f"Token: {token}")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("id")
        email: str = payload.get("email")
        username: str = payload.get("username")

        # User must have either user_id (DB user) or username (LDAP user)
        if user_id is None and username is None:
            raise credentials_exception

        token_data = TokenData(id=user_id, email=email, username=username)
    except (ExpiredSignatureError, InvalidTokenError):
        raise credentials_exception
    
    # Retrieve user from database if user_id is present
    if user_id is not None:
        user = db.query(User).filter(User.id == token_data.id).first()
    else:
        user = User(email=token_data.username, password="")  # Dummy user for LDAP-authenticated users
        
    if user is None:
        raise credentials_exception
    
    return user

# Validation function for customers
def validate_customer(db: Session, data: dict, customer_id: Optional[int] = None):
    errors = {}
    
    # Validate faculty exists
    if 'faculty_id' in data:
        faculty = db.query(Faculty).filter(Faculty.id == data['faculty_id']).first()
        if not faculty:
            errors['faculty_id'] = 'Faculty not found'
        
    if 'department_id' in data and data['department_id'] is not None:
        department = db.query(Department).filter(Department.id == data['department_id']).first()
        if not department:
            errors['department_id'] = 'Department not found'
        elif 'faculty_id' in data and department.faculty_id != data['faculty_id']:
            errors['department_id'] = 'Department does not belong to the selected faculty'
    
    
    if 'name' not in data or not isinstance(data['name'], str) or len(data['name']) > 255:
        errors['name'] = 'Name is required and must be a string with a maximum of 255 characters.'

    if 'email' not in data or not isinstance(data['email'], str) or len(data['email']) > 255:
        errors['email'] = 'Email is required and must be a string with a maximum of 255 characters.'
    else:
        query = db.query(Customer).filter(Customer.email == data['email'])
        if customer_id:
            query = query.filter(Customer.id != customer_id)
        existing_customer = query.first()
        if existing_customer:
            errors['email'] = 'Email must be unique.'

    return errors

#
# Authentication Routes
#
@app.post("/api/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(user: RegisterSchema, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists."
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, password=hashed_password)
    
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        return {
            "status": True,
            "message": "User registered successfully.",
            "data": {}
        }
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists."
        )

@app.post("/api/login", response_model=TokenResponse)
def login(user_data: LoginSchema, db: Session = Depends(get_db)):
    """Login user and return JWT token"""
    user = db.query(User).filter(User.email == user_data.email).first()
    
    if not user or not verify_password(user_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    
    # Create access token
    access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    access_token = create_access_token(
        data={"id": user.id, "email": user.email},
        expires_delta=access_token_expires
    )
    
    return {
        "status": True,
        "message": "Login successful.",
        "data": {
            "id": user.id,
            "email": user.email,
            "token": access_token
        }
    }

@app.post("/api/loginldap", response_model=TokenResponse)
async def loginldap(user_data: LoginSchema):

    """Login user and return JWT token"""
    user_data.email = user_data.email.replace("@pmf.kg.ac.rs", "")
    user_data.email = user_data.email.replace("@kg.ac.rs", "")
    user = await ldap_auth.authenticate_user(user_data.email, user_data.password)

    # Only allow users in LDAP_USER_LIST
    if not user or user_data.email not in config.LDAP_USER_LIST:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )
    
    # Create access token
    access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    access_token = create_access_token(
        data={"username": user.username, "email": user.email },
        expires_delta=access_token_expires
    )
    
    return {
        "status": True,
        "message": "Login successful.",
        "data": {
            "username": user.username,
            "email": user.email,
            "token": access_token
        }
    }


@app.post("/api/logout", response_model=ProfileResponse)
#def logout(current_user: User = Depends(get_current_user)):
def logout():
    """Logout user"""
    # In JWT, logout is client-side (remove token)
    return {
        "status": True,
        "message": "Logout successful.",
        "data": {}
    }

@app.get("/api/profile", response_model=ProfileResponse)
def profile(current_user: User = Depends(get_current_user)):
    """Get user profile"""
    return {
        "status": True,
        "message": "User profile retrieved successfully.",
        "data": {"id": current_user.id, "email": current_user.email}
    }

#
# Faculty GET routes
#
@app.get("/api/faculties", response_model=List[FacultyResponse])
def get_faculties(db: Session = Depends(get_db)):
    """Get all faculties"""
    return db.query(Faculty).all()

@app.get("/api/faculties/{faculty_id}", response_model=FacultyResponse)
def get_faculty(faculty_id: int, db: Session = Depends(get_db)):
    """Get a specific faculty by ID"""
    faculty = db.query(Faculty).filter(Faculty.id == faculty_id).first()
    if not faculty:
        raise HTTPException(status_code=404, detail="Faculty not found")
    return faculty

#
# Department GET routes
#
@app.get("/api/departments", response_model=List[DepartmentResponse])
def get_departments(
    faculty_id: Optional[int] = Query(None, description="Filter by faculty ID"),
    db: Session = Depends(get_db)
):
    """Get all departments, optionally filtered by faculty"""
    query = db.query(Department)
    if faculty_id:
        query = query.filter(Department.faculty_id == faculty_id)
    return query.all()

@app.get("/api/departments/{department_id}", response_model=DepartmentResponse)
def get_department(department_id: int, db: Session = Depends(get_db)):
    """Get a specific department by ID"""
    department = db.query(Department).filter(Department.id == department_id).first()
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")
    return department

#
# Customer Routes
#
@app.get("/api/customers", response_model=CustomersListDataResponse)
def get_customers(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(10, ge=1, le=100, description="Items per page"),
    filter_string: Optional[str] = Query(None, description="Filter by customer name, email, ORCID, Scopus ID, ECRIS ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all customers with pagination and filtering"""
    # Start with base query
    query = db.query(Customer)
    
    # Apply filter_string filter if provided
    if filter_string is not None:
        query = query.filter(
            or_(
            Customer.name.ilike(f"%{filter_string}%"),
            Customer.email.ilike(f"%{filter_string}%"),
            Customer.orcid.ilike(f"%{filter_string}%"), 
            Customer.scopusid.ilike(f"%{filter_string}%"),
            Customer.ecrisid.ilike(f"%{filter_string}%"),
            )
        )

    total = query.count()
    
    # Calculate offset
    offset = (page - 1) * per_page
    
    # Get customers for current page
    customers = query.offset(offset).limit(per_page).all()
    
    # Calculate total pages
    total_pages = (total + per_page - 1) // per_page
    
    return {
        "status": True,
        "message": "Customers retrieved successfully",
        "data": customers,
        "paging": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_items": total
        }
    }

@app.post("/api/customers", response_model=CustomerDataResponse, status_code=status.HTTP_201_CREATED)
def create_customer(
    customer: CustomerCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new customer"""
    # Validate customer data
    errors = validate_customer(db, customer.model_dump())
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "status": False,
                "message": "Validation error",
                "errors": errors
            }
        )
    
    try:
        new_customer = Customer(**customer.model_dump())
        db.add(new_customer)
        db.commit()
        db.refresh(new_customer)
        
        return {
            "status": True,
            "message": "Customer created successfully",
            "data": new_customer
        }
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "status": False,
                "message": "Email, ORCID, Scopus ID, ECRIS ID must be unique."
            }
        )

@app.get("/api/customers/{customer_id}", response_model=CustomerDataResponse)
def get_customer(
    customer_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific customer by ID"""
    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "status": False,
                "message": "Customer not found"
            }
        )
    
    return {
        "status": True,
        "message": "Customer found successfully",
        "data": customer
    }

@app.put("/api/customers/{customer_id}", response_model=CustomerDataResponse)
def update_customer(
    customer_id: int,
    customer_update: CustomerUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a customer"""
    # Get existing customer
    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "status": False,
                "message": "Customer not found"
            }
        )
    
    # Validate customer data
    errors = validate_customer(db, customer_update.model_dump(), customer_id)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "status": False,
                "message": "Validation error",
                "errors": errors
            }
        )
    
    try:
        # Update customer
        for field, value in customer_update.model_dump().items():
            setattr(customer, field, value)
        
        db.commit()
        db.refresh(customer)
        
        return {
            "status": True,
            "message": "Customer updated successfully",
            "data": customer
        }
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "status": False,
                "message": "Email and ORCID must be unique."
            }
        )

@app.delete("/api/customers/{customer_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_customer(
    customer_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a customer"""
    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "status": False,
                "message": "Customer not found"
            }
        )
    
    db.delete(customer)
    db.commit()
    
    return None

@app.get("/api/customers/download/csv")
def download_customers_csv(db: Session = Depends(get_db)):
    """Download all customers as CSV (unprotected route)"""
    customers = db.query(Customer).all()
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=['orcid', 'ecrisid', 'scopusid', 'name', 'email', 'department', 'faculty']
    )
    
    writer.writeheader()
    
    for customer in customers:
        # Get department and faculty names
        department_name = customer.department.name if customer.department else ''
        faculty_name = customer.faculty.name if customer.faculty else ''
        
        writer.writerow({
            'orcid': customer.orcid or '',
            'ecrisid': customer.ecrisid or '',
            'scopusid': customer.scopusid or '',
            'name': customer.name,
            'email': customer.email,
            'department': department_name,
            'faculty': faculty_name
        })
    
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=researchers.csv"}
    )

#
# Error handlers
#
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": False,
            "message": exc.detail.get("message", str(exc.detail)) if isinstance(exc.detail, dict) else str(exc.detail),
            "errors": exc.detail.get("errors", None) if isinstance(exc.detail, dict) else None
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
    