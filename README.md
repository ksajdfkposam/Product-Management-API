﻿# Product-Management-API
Clone the repository:
git clone <repository-url>
cd Backend-API
Install dependencies:
npm install
Create a .env file and add the following:
JWT_SECRET=your_jwt_secret
Start the server:
node index.js

API Endpoints
Authentication
1. Merchant Registration
Endpoint: POST /auth/register
Description: Register a new merchant with a role.

2. Merchant Login
Endpoint: POST /auth/login
Description: Log in to get a JWT token.

Product Management
1. Create a Product
Endpoint: POST /products
Role Access: Admin only


Here’s a README.md file with detailed API documentation:

Product Management API with RBAC
This is a backend API built with Node.js and MongoDB that provides Role-Based Access Control (RBAC) for managing products. It uses JWT-based authentication and supports CRUD operations for product management.

Features
Role-Based Access Control (RBAC):
Admin: Can create, view, update, and delete products.
Manager: Can view and update products.
Viewer: Can only view products.
JWT Authentication: Secure authentication for all protected routes.
Input Validation: Ensures valid data for registration and product operations.
Error Handling: Graceful handling of unauthorized access, invalid inputs, and other errors.
Prerequisites
Node.js installed
MongoDB running locally or in the cloud
Environment variables configured in .env
Installation
Clone the repository:
bash
Copy code
git clone <repository-url>
cd product-management-api
Install dependencies:
bash
Copy code
npm install
Create a .env file and add the following:
env
Copy code
PORT=5000
MONGO_URI=mongodb://localhost:27017/productManagement
JWT_SECRET=your_jwt_secret
Start the server:
bash
Copy code
npm run dev
API Endpoints
Authentication
1. Merchant Registration
Endpoint: POST /auth/register
Description: Register a new merchant with a role.

Request Body:

json
Copy code
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "StrongPass@123",
  "role": "admin"
}
Response:

json
Copy code
{
  "message": "Registration successful."
}
2. Merchant Login
Endpoint: POST /auth/login
Description: Log in to get a JWT token.

Request Body:

json
Copy code
{
  "email": "john@example.com",
  "password": "StrongPass@123"
}
Response:

json
Copy code
{
  "token": "JWT_TOKEN_HERE"
}
Product Management
1. Create a Product
Endpoint: POST /products
Role Access: Admin only

Request Header:

json
Copy code
{
  "Authorization": "Bearer JWT_TOKEN"
}
Request Body:

json
Copy code
{
  "name": "Product A",
  "price": 100,
  "quantity": 50
}
Response:

json
Copy code
{
  "_id": "64abc1234567890",
  "merchantId": "64def0987654321",
  "name": "Product A",
  "price": 100,
  "quantity": 50,
  "createdAt": "2024-12-11T10:00:00.000Z",
  "updatedAt": "2024-12-11T10:00:00.000Z"
}
2. Retrieve All Products
Endpoint: GET /products
Role Access: Admin, Manager, Viewer

3. Update a Product
Endpoint: PUT /products/:productId
Role Access: Admin, Manager

4. Delete a Product
Endpoint: DELETE /products/:productId
Role Access: Admin only
