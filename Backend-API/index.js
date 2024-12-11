// Import dependencies
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const { body, validationResult } = require('express-validator');
const db=require('./middleware/dbConnect');
const authMiddleware = require('./middleware/auth');
const roleMiddleware = require('./middleware/role');
//const MONGO_URI="mongodb://127.0.0.1:27017/Management"
// Load environment variables
dotenv.config();

// Initialize Express
const app = express();
app.use(express.json());

// Connect to MongoDB
/*mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));*/

// Define Schemas and Models
const merchantSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, enum: ['admin', 'manager', 'viewer'], required: true }
});

const productSchema = new mongoose.Schema({
    merchantId: mongoose.Schema.Types.ObjectId,
    name: String,
    price: { type: Number, min: 0 },
    quantity: { type: Number, min: 0 }
});

const Merchant = mongoose.model('Merchant', merchantSchema);
const Product = mongoose.model('Product', productSchema);

// Utility functions
const generateToken = (merchant) => {
    return jwt.sign({ id: merchant._id, role: merchant.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Routes
// 1. Merchant Registration
app.post('/auth/register', [
    body('email').isEmail(),
    body('password').isStrongPassword(),
    body('role').isIn(['admin', 'manager', 'viewer'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, password, role } = req.body;
    console.log(name," ", email," ", role)
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const merchant = new Merchant({ name, email, password: hashedPassword, role });
        await merchant.save();
        res.status(201).json({ message: 'Merchant registered successfully' });
    } catch (err) {
        if (err.code === 11000) {
            res.status(400).json({ error: 'Email already in use' });
        } else {
            res.status(500).json({ error: 'Server error' });
        }
    }
});

// 2. Merchant Login
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(email)
    try {
        const merchant = await Merchant.findOne({ email });
        if (!merchant || !(await bcrypt.compare(password, merchant.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = generateToken(merchant);
        res.status(200).json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Product Management Routes
// 1. Create a Product (Admin only)
app.post('/products', authMiddleware, roleMiddleware(['admin']), async (req, res) => {
    const { name, price, quantity } = req.body;
    try {
        const product = new Product({ merchantId: req.user.id, name, price, quantity });
        await product.save();
        res.status(201).json({ message: 'Product created successfully', product });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// 2. Retrieve All Products
app.get('/products', authMiddleware, async (req, res) => {
    try {
        const products = await Product.find({ merchantId: req.user.id });
        res.status(200).json(products);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// 3. Update a Product (Admin, Manager only)
app.put('/products/:productId', authMiddleware, roleMiddleware(['admin', 'manager']), async (req, res) => {
    const { productId } = req.params;
    const updates = req.body;
    try {
        const product = await Product.findOneAndUpdate(
            { _id: productId, merchantId: req.user.id },
            updates,
            { new: true }
        );
        if (!product) return res.status(404).json({ error: 'Product not found' });
        res.status(200).json({ message: 'Product updated successfully', product });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// 4. Delete a Product (Admin only)
app.delete('/products/:productId', authMiddleware, roleMiddleware(['admin']), async (req, res) => {
    const { productId } = req.params;
    try {
        const product = await Product.findOneAndDelete({ _id: productId, merchantId: req.user.id });
        if (!product) return res.status(404).json({ error: 'Product not found' });
        res.status(200).json({ message: 'Product deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
