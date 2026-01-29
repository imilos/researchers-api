from datetime import datetime, timedelta
from flask import Flask, redirect, request, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
import jwt
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional

from flask_openapi3 import Info, Tag, OpenAPI

info = Info(title="Customer API", version="1.0.0")
app = OpenAPI(__name__, info=info)

CORS(app)  # Allow CORS for all routes
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///customers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '122233mkdsjadkasdk'

db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Define tags
customer_tag = Tag(name="customer", description="Customer operations")
auth_tag = Tag(name="authentication", description="User authentication")

# Models
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.request_loader
def load_user_from_request(request):
    # Try to get token from Authorization header
    auth_header = request.headers.get('Authorization')
    if auth_header:
        try:
            # Extract token from "Bearer <token>"
            token = auth_header.split(' ')[1]
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            # Get user from database
            user_id = data['id']
            return User.query.get(user_id)
        except (IndexError, jwt.ExpiredSignatureError, jwt.InvalidTokenError, KeyError):
            return None
    return None

# Pydantic Schemas for OpenAPI
class CustomerPath(BaseModel):
    customer_id: int

class CustomerBase(BaseModel):
    name: str = Field(..., max_length=255, description="Customer name")
    email: str = Field(..., max_length=255, description="Customer email")

class CustomerCreate(CustomerBase):
    pass

class CustomerUpdate(CustomerBase):
    pass

class CustomerResponse(BaseModel):
    id: int
    name: str
    email: str
    
    model_config = ConfigDict(from_attributes=True)

class CustomerListResponse(BaseModel):
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

# Validation function for customers
def validate_customer(data, customer_id=None):
    errors = {}
    
    if 'name' not in data or not isinstance(data['name'], str) or len(data['name']) > 255:
        errors['name'] = 'Name is required and must be a string with a maximum of 255 characters.'

    if 'email' not in data or not isinstance(data['email'], str) or len(data['email']) > 255:
        errors['email'] = 'Email is required and must be a string with a maximum of 255 characters.'
    else:
        existing_customer = Customer.query.filter_by(email=data['email']).first()
        if existing_customer and (customer_id is None or existing_customer.id != customer_id):
            errors['email'] = 'Email must be unique.'

    return errors

# Customer Routes
@app.get('/api/customers', tags=[customer_tag])
@login_required
def get_customers():
    """Get all customers with pagination
    ---
    responses:
      200:
        description: List of customers
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CustomerListResponse'
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    customers_query = Customer.query.paginate(page=page, per_page=per_page, error_out=False)
    customers = customers_query.items

    return {
        'status': True,
        'message': 'Customers retrieved successfully',
        'data': [{'id': c.id, 'name': c.name, 'email': c.email} for c in customers],
        'paging': {
            'page': customers_query.page,
            'per_page': customers_query.per_page,
            'total_pages': customers_query.pages,
            'total_items': customers_query.total
        }
    }

@app.post('/api/customers', tags=[customer_tag])
@login_required
def create_customer(body: CustomerCreate):
    """Create a new customer
    ---
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/CustomerCreate'
    responses:
      201:
        description: Customer created successfully
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CustomerResponse'
      422:
        description: Validation error
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    data = body.model_dump()
    errors = validate_customer(data)
    if errors:
        return {
            'status': False,
            'message': 'Validation error',
            'errors': errors
        }, 422

    try:
        customer = Customer(name=data['name'], email=data['email'])
        db.session.add(customer)
        db.session.commit()
        return {
            'status': True,
            'message': 'Customer created successfully',
            'data': {'id': customer.id, 'name': customer.name, 'email': customer.email}
        }, 201
    except IntegrityError:
        db.session.rollback()
        return {
            'status': False,
            'message': 'Email must be unique.'
        }, 422

@app.get('/api/customers/<int:customer_id>', tags=[customer_tag])
@login_required
def get_customer(path: CustomerPath):
    """Get a specific customer by ID
    ---
    parameters:
      - name: customer_id
        in: path
        required: true
        schema:
          type: integer
    responses:
      200:
        description: Customer found
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CustomerResponse'
      404:
        description: Customer not found
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    customer_id = path.customer_id
    customer = Customer.query.get_or_404(customer_id)
    return {
        'status': True,
        'message': 'Customer found successfully',
        'data': {'id': customer.id, 'name': customer.name, 'email': customer.email}
    }

@app.put('/api/customers/<int:customer_id>', tags=[customer_tag])
@login_required
def update_customer(path: CustomerPath, body: CustomerUpdate):
    """Update a customer
    ---
    parameters:
      - name: customer_id
        in: path
        required: true
        schema:
          type: integer
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/CustomerUpdate'
    responses:
      200:
        description: Customer updated successfully
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CustomerResponse'
      422:
        description: Validation error
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    customer_id = path.customer_id
    data = body.model_dump()
    
    errors = validate_customer(data, customer_id)
    if errors:
        return {
            'status': False,
            'message': 'Validation error',
            'errors': errors
        }, 422

    customer = Customer.query.get_or_404(customer_id)
    customer.name = data['name']
    customer.email = data['email']
    db.session.commit()

    return {
        'status': True,
        'message': 'Customer updated successfully',
        'data': {'id': customer.id, 'name': customer.name, 'email': customer.email}
    }

@app.delete('/api/customers/<int:customer_id>', tags=[customer_tag])
@login_required
def delete_customer(path: CustomerPath):
    """Delete a customer
    ---
    parameters:
      - name: customer_id
        in: path
        required: true
        schema:
          type: integer
    responses:
      204:
        description: Customer deleted successfully
      404:
        description: Customer not found
    """
    customer_id = path.customer_id
    customer = Customer.query.get_or_404(customer_id)
    db.session.delete(customer)
    db.session.commit()
    return '', 204

# Authentication Routes
@app.post('/api/register', tags=[auth_tag])
def register(body: RegisterSchema):
    """Register a new user
    ---
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/RegisterSchema'
    responses:
      201:
        description: User registered successfully
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TokenResponse'
      400:
        description: Registration error
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    data = body.model_dump()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return {
            'status': False,
            'message': 'Email and password are required.'
        }, 400
    
    if len(password) < 6:
        return {
            'status': False,
            'message': 'Password must be at least 6 characters long.'
        }, 400
    
    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password=hashed_password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return {
            'status': True,
            'message': 'User registered successfully.'
        }, 201
    except IntegrityError:
        db.session.rollback()
        return {
            'status': False,
            'message': 'Email already exists.'
        }, 400

@app.post('/api/login', tags=[auth_tag])
def login(body: LoginSchema):
    """Login user and return JWT token
    ---
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/LoginSchema'
    responses:
      200:
        description: Login successful
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TokenResponse'
      401:
        description: Invalid credentials
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    data = body.model_dump()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return {
            'status': False,
            'message': 'Email and password are required.'
        }, 400

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        login_user(user)

        # Generate the JWT token
        token = jwt.encode(
            {
                'id': user.id,
                'email': user.email,
                'exp': datetime.utcnow() + timedelta(hours=2)
            },
            app.config['SECRET_KEY']
        )

        return {
            'status': True,
            'message': 'Login successful.',
            'data': {
                'id': user.id,
                'email': user.email,
                'token': token
            }
        }
    else:
        return {
            'status': False,
            'message': 'Invalid email or password.'
        }, 401

@app.post('/api/logout', tags=[auth_tag])
#@login_required
def logout():
    """Logout user
    ---
    responses:
      200:
        description: Logout successful
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ProfileResponse'
    """
    logout_user()
    return {
        'status': True,
        'message': 'Logout successful.'
    }

@app.get('/api/profile', tags=[auth_tag])
@login_required
def profile():
    """Get user profile
    ---
    responses:
      200:
        description: User profile retrieved
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ProfileResponse'
    """
    return {
        'status': True,
        'message': 'User profile retrieved successfully.',
        'data': {'id': current_user.id, 'email': current_user.email}
    }

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Access OpenAPI documentation at:
    # - Swagger UI: http://localhost:8000/openapi
    # - ReDoc: http://localhost:8000/redoc
    # - OpenAPI JSON: http://localhost:8000/openapi.json
    app.run(debug=True, port=8000)