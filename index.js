const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2; // Fixed import for CommonJS
const streamifier = require('streamifier'); // To convert buffer to stream for Cloudinary
const User = require('./models/User'); // Import the User model
const connectDB = require('./db');     // Import the connectDB function

require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const mongoURI = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;

// Configure Cloudinary
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'dv4ykvlb6',
  api_key: process.env.CLOUDINARY_API_KEY || '177374188693799',
  api_secret: process.env.CLOUDINARY_API_SECRET // Ensure this is set in your environment variables
});

// Middleware
app.use(cors({
  origin: ['https://deceodingayush-github-io.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// Connect to MongoDB
if (mongoURI) {
  connectDB(mongoURI);
} else {
  console.error('MONGO_URI environment variable not found. Please create a .env file in the server directory.');
  process.exit(1);
}

// Multer setup for profile pictures (using memory storage instead of disk storage)
const storage = multer.memoryStorage(); // Store file in memory instead of disk

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'image/png' || file.mimetype === 'image/jpeg') {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 5 }, // 5MB limit
  fileFilter: fileFilter,
});

// Middleware to extract user ID from token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  console.log('Auth Header:', authHeader);
  console.log('Token:', token);

  if (token == null) {
    console.log('No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.sendStatus(403);
    }
    console.log('Token verified, user:', user);
    req.userId = user.userId;
    next();
  });
};

// API Endpoints
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ message: 'Email or username already exists' });
    }
    const newUser = new User({ username, email, password, profilePicture: 'default.png' });
    await newUser.save();
    console.log('User saved successfully:', newUser.username);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Error registering user' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      console.log('Login attempt failed: User not found -', username);
      return res.status(400).json({ message: 'Invalid username' });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      console.log('Login attempt failed: Invalid password for user -', username);
      return res.status(400).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ userId: user._id }, jwtSecret, { expiresIn: '1h' });
    console.log('Login successful for user:', username);
    
    res.json({ 
      token, 
      userId: user._id, 
      username: user.username,
      profilePicture: user.profilePicture 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'An error occurred during login' });
  }
});

app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ message: 'Error fetching profile' });
  }
});

app.patch('/api/profile', authenticateToken, async (req, res) => {
  console.log('Received PATCH request to /api/profile');
  console.log('Request body:', req.body);
  try {
    const { bio } = req.body;
    if (!bio) {
      return res.status(400).json({ message: 'Bio is required' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { bio },
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Bio updated successfully', user: updatedUser });
  } catch (error) {
    console.error('Error updating bio:', error);
    res.status(500).json({ message: 'Error updating bio', error: error.message });
  }
});

app.post('/api/profile/upload', authenticateToken, upload.single('profilePicture'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Upload the file to Cloudinary using a stream
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'profile_pictures', // Store in a specific folder in Cloudinary
        public_id: `profilePicture-${req.userId}-${Date.now()}`, // Unique public ID
        overwrite: true,
        fetch_format: 'auto', // Optimize format
        quality: 'auto' // Optimize quality
      },
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          return res.status(500).json({ message: 'Error uploading to Cloudinary', error: error.message });
        }

        // Update the user's profile picture with the Cloudinary URL
        User.findByIdAndUpdate(req.userId, { profilePicture: result.secure_url }, { new: true })
          .then(() => {
            res.json({ message: 'Profile picture uploaded successfully', filename: result.secure_url });
          })
          .catch((updateError) => {
            console.error('Error updating user profile picture:', updateError);
            res.status(500).json({ message: 'Error updating profile picture in database', error: updateError.message });
          });
      }
    );

    // Convert the file buffer to a stream and pipe it to Cloudinary
    streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
  } catch (error) {
    console.error('Error uploading profile picture:', error);
    res.status(500).json({ message: 'Error uploading profile picture', error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
