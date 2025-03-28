const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
// Remove cors import since we're letting Nginx handle it
require('dotenv').config();

const app = express();
app.use(express.json());

// Remove all CORS configuration from Express

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/fileUploadApp')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

const User = mongoose.model('User', userSchema);

// File Schema
const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalname: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  uploadDate: { type: Date, default: Date.now }
});

const File = mongoose.model('File', fileSchema);

// Auth middleware
const authenticate = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Configure EBS volume storage path
const EBS_UPLOAD_PATH = process.env.EBS_UPLOAD_PATH || '/mnt/ebs-volume/uploads';

// Ensure upload directory exists
if (!fs.existsSync(EBS_UPLOAD_PATH)) {
  fs.mkdirSync(EBS_UPLOAD_PATH, { recursive: true });
}

// Configure multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Create user-specific directory
    const userDir = path.join(EBS_UPLOAD_PATH, req.user.id);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    // Generate unique filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

// Configure multer upload (no file size or type restrictions)
const upload = multer({
  storage: storage,
  limits: { fileSize: Infinity } // No file size limit
});

// Routes
// Register user
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    // Create new user
    const user = new User({ username, password, email });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login user
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'your_jwt_secret',
      { expiresIn: '12h' }
    );

    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Profile endpoint
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Improved file upload endpoint
app.post('/api/upload', authenticate, (req, res) => {
  // Set timeout for large uploads
  req.setTimeout(600000); // 10 minutes timeout
  
  // Log upload start
  console.log(`File upload started for user: ${req.user.id}`);
  
  upload.single('file')(req, res, async (err) => {
    try {
      if (err) {
        console.error('Upload error:', err);
        return res.status(400).json({ message: err.message });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
      }

      // Log successful upload
      console.log(`File uploaded: ${req.file.originalname}, size: ${req.file.size} bytes`);

      // Save file info to database
      const file = new File({
        filename: req.file.filename,
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        userId: req.user.id
      });

      await file.save();

      // Remove CORS headers here - let Nginx handle them
      
      res.status(201).json({
        message: 'File uploaded successfully',
        file: {
          id: file._id,
          filename: file.filename,
          originalname: file.originalname,
          size: file.size,
          uploadDate: file.uploadDate
        }
      });
    } catch (error) {
      console.error('Upload processing error:', error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  });
});

// Get user's files
app.get('/api/files', authenticate, async (req, res) => {
  try {
    const files = await File.find({ userId: req.user.id }).sort({ uploadDate: -1 });

    res.json(files.map(file => ({
      id: file._id,
      filename: file.filename,
      originalname: file.originalname,
      mimetype: file.mimetype,
      size: file.size,
      uploadDate: file.uploadDate
    })));
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete file
app.delete('/api/files/:id', authenticate, async (req, res) => {
  try {
    const file = await File.findOne({ _id: req.params.id, userId: req.user.id });

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Delete file from EBS volume
    const filePath = path.join(EBS_UPLOAD_PATH, req.user.id, file.filename);
    
    // Check if file exists before attempting to delete
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    } else {
      console.warn(`File not found on disk: ${filePath}`);
    }

    // Delete file record from database
    await File.deleteOne({ _id: req.params.id });

    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('File deletion error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);

  if (err.name === 'ValidationError') {
    return res.status(400).json({ message: err.message });
  }

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }

  res.status(err.status || 500).json({ message: err.message || 'Something went wrong' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Letting Nginx handle CORS for origin: https://orincore.com`);
});

module.exports = app;
