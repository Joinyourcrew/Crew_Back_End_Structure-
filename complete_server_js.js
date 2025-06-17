const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv-safe');
const passport = require('passport');
const TwitterStrategy = require('passport-twitter').Strategy;
const session = require('express-session');
const MongoStore = require('connect-mongo');
const jwt = require('jsonwebtoken');
const { Keypair, PublicKey, Connection, clusterApiUrl, Transaction, SystemProgram, LAMPORTS_PER_SOL } = require('@solana/web3.js');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const crypto = require('crypto');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const { Server } = require('socket.io');
const projectRoutes = require('./routes/projects');
const User = require('./models/User');
const Project = require('./models/Project');
const Message = require('./models/Message');
const GroupMessage = require('./models/GroupMessage');

// Load environment variables
dotenv.config({
  allowEmptyValues: false,
  example: '.env.example',
});

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Compression middleware
app.use(compression());

// Logging middleware
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// Enhanced CORS Configuration
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'];
    if (process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));

// Body parsing middleware with limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced Rate Limiting
const createRateLimiter = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message },
  standardHeaders: true,
  legacyHeaders: false,
});

// Different rate limits for different endpoints
const authLimiter = createRateLimiter(15 * 60 * 1000, 5, 'Too many authentication attempts');
const apiLimiter = createRateLimiter(15 * 60 * 1000, 100, 'Too many API requests');
const walletLimiter = createRateLimiter(15 * 60 * 1000, 10, 'Too many wallet operations');

app.use('/auth/', authLimiter);
app.use('/api/', apiLimiter);
app.use('/api/wallet/', walletLimiter);

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGO_URI,
    touchAfter: 24 * 3600 // lazy session update
  }),
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    sameSite: 'strict'
  },
  name: 'sessionId' // Don't use default session name
}));

app.use(passport.initialize());
app.use(passport.session());

// Enhanced MongoDB Connection with retry logic
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      bufferCommands: false,
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('MongoDB connection error:', error);
    // Retry connection after 5 seconds
    setTimeout(connectDB, 5000);
  }
};

connectDB();

// Handle MongoDB connection events
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected. Attempting to reconnect...');
  connectDB();
});

// Enhanced Passport Twitter Strategy
passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_CONSUMER_KEY,
  consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
  callbackURL: process.env.TWITTER_CALLBACK_URL || 'http://localhost:5000/auth/x/callback',
}, async (token, tokenSecret, profile, done) => {
  try {
    let user = await User.findOne({ twitterId: profile.id });
    
    if (!user) {
      user = new User({
        twitterId: profile.id,
        xUsername: profile.username,
        displayName: profile.displayName,
        profilePic: profile.photos?.[0]?.value || 'https://via.placeholder.com/50',
        createdAt: new Date(),
        lastLogin: new Date(),
      });
    } else {
      // Update last login
      user.lastLogin = new Date();
      // Update profile info if changed
      user.displayName = profile.displayName;
      user.profilePic = profile.photos?.[0]?.value || user.profilePic;
    }
    
    await user.save();
    done(null, user);
  } catch (error) {
    console.error('Twitter auth error:', error);
    done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    console.error('User deserialization error:', error);
    done(error);
  }
});

// Solana connection
const connection = new Connection(
  process.env.SOLANA_RPC_URL || clusterApiUrl('devnet'),
  'confirmed'
);

// Phantom wallet authentication utilities
function generateAuthMessage(publicKey, timestamp) {
  return `Sign this message to authenticate with Crew Platform.\n\nWallet: ${publicKey}\nTimestamp: ${timestamp}\n\nThis request will not trigger a blockchain transaction or cost any gas fees.`;
}

function verifySignature(message, signature, publicKey) {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = bs58.decode(signature);
    const publicKeyBytes = new PublicKey(publicKey).toBytes();
    
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

async function getWalletBalance(publicKey) {
  try {
    const balance = await connection.getBalance(new PublicKey(publicKey));
    return balance / LAMPORTS_PER_SOL;
  } catch (error) {
    console.error('Balance fetch error:', error);
    throw new Error('Failed to fetch wallet balance');
  }
}

async function validateWalletOwnership(publicKey, signature, message) {
  try {
    // Verify the signature
    const isValid = verifySignature(message, signature, publicKey);
    if (!isValid) {
      throw new Error('Invalid signature');
    }
    
    // Optional: Check if wallet has minimum balance (0.001 SOL for example)
    const balance = await getWalletBalance(publicKey);
    if (balance < 0.001) {
      console.warn(`Wallet ${publicKey} has low balance: ${balance} SOL`);
      // Don't throw error, just log warning
    }
    
    return true;
  } catch (error) {
    console.error('Wallet ownership validation error:', error);
    throw error;
  }
}

const requiredEnvVars = ['JWT_SECRET', 'ENCRYPTION_KEY', 'MONGO_URI', 'SESSION_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
  console.log('Please create a .env file with the required variables');
  // Don't exit in development, use defaults
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
}

// JWT and Encryption Keys with validation
const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret-for-development';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
  console.warn('ENCRYPTION_KEY should be a 32-byte hex string (64 characters)');
}

// Enhanced Wallet Encryption with authentication tag
function encryptSecretKey(secretKey, key) {
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    
    let encrypted = cipher.update(secretKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return { 
      iv: iv.toString('hex'), 
      encrypted: encrypted,
      authTag: authTag.toString('hex')
    };
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt secret key');
  }
}

function decryptSecretKey(encryptedData, key) {
  try {
    const { iv, encrypted, authTag } = JSON.parse(encryptedData);
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt secret key');
  }
}

// Enhanced wallet generation with better error handling
async function generateAndStoreWallet(user) {
  try {
    if (user.walletPublicKey && user.encryptedSecretKey) {
      return { publicKey: user.walletPublicKey };
    }
    
    const keypair = Keypair.generate();
    const publicKey = keypair.publicKey.toString();
    const secretKey = Buffer.from(keypair.secretKey).toString('hex');
    
    const encryptedData = encryptSecretKey(secretKey, ENCRYPTION_KEY);
    
    user.walletPublicKey = publicKey;
    user.encryptedSecretKey = JSON.stringify(encryptedData);
    user.walletType = 'generated';
    
    await user.save();
    
    return { publicKey };
  } catch (error) {
    console.error('Wallet generation error:', error);
    throw new Error('Failed to generate wallet');
  }
}

// Enhanced Phantom wallet connection with proper validation
async function connectPhantomWallet(user, publicKey, signature, timestamp) {
  try {
    // Validate inputs
    if (!publicKey || typeof publicKey !== 'string') {
      throw new Error('Invalid public key: must be a string');
    }
    
    if (!signature || typeof signature !== 'string') {
      throw new Error('Invalid signature: must be a string');
    }
    
    if (!timestamp || typeof timestamp !== 'number') {
      throw new Error('Invalid timestamp: must be a number');
    }
    
    // Check timestamp is recent (within 5 minutes)
    const now = Date.now();
    const timeDiff = Math.abs(now - timestamp);
    if (timeDiff > 5 * 60 * 1000) {
      throw new Error('Timestamp too old or invalid');
    }
    
    // Validate Solana public key format
    try {
      new PublicKey(publicKey);
    } catch (error) {
      throw new Error('Invalid Solana public key format');
    }
    
    // Generate and verify auth message
    const authMessage = generateAuthMessage(publicKey, timestamp);
    await validateWalletOwnership(publicKey, signature, authMessage);
    
    // Check if wallet is already connected to another user
    const existingUser = await User.findOne({ 
      walletPublicKey: publicKey,
      _id: { $ne: user._id }
    });
    
    if (existingUser) {
      throw new Error('This wallet is already connected to another account');
    }
    
    // Update user with wallet info
    user.walletPublicKey = publicKey;
    user.encryptedSecretKey = null; // No secret key for external wallets
    user.walletType = 'phantom';
    user.walletConnectedAt = new Date();
    
    await user.save();
    
    // Get wallet balance for response
    const balance = await getWalletBalance(publicKey);
    
    return { 
      publicKey,
      balance,
      type: 'phantom'
    };
  } catch (error) {
    console.error('Phantom wallet connection error:', error);
    throw new Error(`Failed to connect Phantom wallet: ${error.message}`);
  }
}

// Enhanced JWT verification middleware
async function verifyXToken(req, res, next) {
  try {
    const token = req.cookies.jwt || req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ xUsername: decoded.xUsername });
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    
    console.error('Token verification error:', error);
    return res.status(500).json({ error: 'Authentication error' });
  }
}

// Authentication Routes
app.get('/auth/x', passport.authenticate('twitter'));

app.get('/auth/x/callback', 
  passport.authenticate('twitter', { failureRedirect: '/signup.html?error=auth_failed' }), 
  (req, res) => {
    try {
      const token = jwt.sign(
        { 
          xUsername: req.user.xUsername,
          userId: req.user._id 
        }, 
        JWT_SECRET, 
        { expiresIn: '24h' }
      );
      
      res.cookie('jwt', token, { 
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production', 
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      
      res.redirect('/dashboard.html');
    } catch (error) {
      console.error('Callback error:', error);
      res.redirect('/signup.html?error=token_creation_failed');
    }
  }
);

// Logout route
app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('jwt');
    res.json({ message: 'Logged out successfully' });
  });
});

// User profile route
app.get('/api/user/profile', verifyXToken, (req, res) => {
  const { password, encryptedSecretKey, ...safeUser } = req.user.toObject();
  res.json(safeUser);
});

// Phantom Wallet Authentication and Connection Routes

// Generate auth message for wallet connection
app.post('/api/wallet/auth-message', verifyXToken, (req, res) => {
  try {
    const { publicKey } = req.body;
    
    if (!publicKey) {
      return res.status(400).json({ error: 'Public key is required' });
    }
    
    // Validate public key format
    try {
      new PublicKey(publicKey);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid public key format' });
    }
    
    const timestamp = Date.now();
    const message = generateAuthMessage(publicKey, timestamp);
    
    res.json({ 
      message,
      timestamp,
      publicKey
    });
  } catch (error) {
    console.error('Auth message generation error:', error);
    res.status(500).json({ error: 'Failed to generate auth message' });
  }
});

// Connect Phantom wallet with signature verification
app.post('/api/wallet/connect-phantom', verifyXToken, async (req, res) => {
  try {
    const { publicKey, signature, timestamp } = req.body;
    
    if (!publicKey || !signature || !timestamp) {
      return res.status(400).json({ 
        error: 'Public key, signature, and timestamp are required' 
      });
    }
    
    const result = await connectPhantomWallet(req.user, publicKey, signature, timestamp);
    
    res.json({ 
      message: 'Phantom wallet connected successfully', 
      wallet: result
    });
  } catch (error) {
    console.error('Phantom wallet connection error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Get wallet information
app.get('/api/wallet/info', verifyXToken, async (req, res) => {
  try {
    if (!req.user.walletPublicKey) {
      return res.status(404).json({ error: 'No wallet connected' });
    }
    
    const balance = await getWalletBalance(req.user.walletPublicKey);
    
    res.json({
      publicKey: req.user.walletPublicKey,
      type: req.user.walletType || 'unknown',
      balance,
      connectedAt: req.user.walletConnectedAt
    });
  } catch (error) {
    console.error('Wallet info error:', error);
    res.status(500).json({ error: 'Failed to fetch wallet information' });
  }
});

// Generate wallet route
app.post('/api/wallet/generate', verifyXToken, async (req, res) => {
  try {
    const result = await generateAndStoreWallet(req.user);
    res.json({ 
      message: 'Wallet generated successfully', 
      publicKey: result.publicKey 
    });
  } catch (error) {
    console.error('Wallet generation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// API Routes
app.use('/api/projects', projectRoutes);

// REST API endpoints for chat (for when WebSocket isn't available)
app.get('/api/chat/:projectId/messages', verifyXToken, async (req, res) => {
  try {
    const { projectId } = req.params;
    const { limit = 50, before } = req.query;
    
    // Verify user is a member of the project
    const project = await Project.findById(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    const isMember = project.acceptedMembers.some(member => 
      member.xUsername === req.user.xUsername
    );
    
    if (!isMember) {
      return res.status(403).json({ error: 'You are not a member of this project' });
    }
    
    let query = { projectId };
    
    // Add pagination
    if (before) {
      query.timestamp = { $lt: new Date(before) };
    }
    
    const messages = await GroupMessage.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .lean();
    
    res.json(messages.reverse());
  } catch (error) {
    console.error('Failed to fetch messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Enhanced Swagger API Documentation
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: { 
      title: 'Crew Platform API', 
      version: '1.0.0',
      description: 'API documentation for the Crew Platform - Web3 Collaboration on Solana'
    },
    servers: [
      { 
        url: process.env.NODE_ENV === 'production' 
          ? process.env.API_BASE_URL 
          : 'http://localhost:5000',
        description: process.env.NODE_ENV === 'production' ? 'Production' : 'Development'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: ['./routes/*.js', './server.js'],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Create HTTP server
const server = require('http').createServer(app);

// WebSocket Integration
const io = new Server(server, {
  cors: corsOptions,
  path: '/socket.io/',
  transports: ['websocket', 'polling']
});

// WebSocket Authentication Middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return next(new Error('Authentication required'));
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ xUsername: decoded.xUsername });
    
    if (!user) {
      return next(new Error('User not found'));
    }
    
    socket.user = user;
    next();
  } catch (error) {
    console.error('Socket auth error:', error);
    next(new Error('Authentication failed'));
  }
});

// WebSocket Connection Handler
io.on('connection', (socket) => {
  console.log(`User ${socket.user.xUsername} connected to chat`);
  
  // Join project room
  socket.on('join-project', async (projectId) => {
    try {
      // Verify user is a member of the project
      const project = await Project.findById(projectId);
      if (!project) {
        socket.emit('error', { message: 'Project not found' });
        return;
      }
      
      const isMember = project.acceptedMembers.some(member => 
        member.xUsername === socket.user.xUsername
      );
      
      if (!isMember) {
        socket.emit('error', { message: 'You are not a member of this project' });
        return;
      }
      
      socket.join(`project-${projectId}`);
      socket.currentProjectId = projectId;
      
      // Send recent messages to the user
      const recentMessages = await GroupMessage.find({ projectId })
        .sort({ timestamp: -1 })
        .limit(50)
        .lean();
      
      socket.emit('message-history', recentMessages.reverse());
      
      // Notify others that user joined
      socket.to(`project-${projectId}`).emit('user-joined', {
        username: socket.user.xUsername,
        profilePic: socket.user.profilePic
      });
      
      console.log(`${socket.user.xUsername} joined project ${projectId}`);
    } catch (error) {
      console.error('Join project error:', error);
      socket.emit('error', { message: 'Failed to join project' });
    }
  });
  
  // Send message
  socket.on('send-message', async (data) => {
    try {
      const { content, projectId, isTask = false, assigneeXUsername } = data;
      
      if (!content || !projectId) {
        socket.emit('error', { message: 'Content and project ID are required' });
        return;
      }
      
      // Verify user is in the project
      if (socket.currentProjectId !== projectId) {
        socket.emit('error', { message: 'You must join the project first' });
        return;
      }
      
      // Create message
      const message = new GroupMessage({
        projectId,
        senderXUsername: socket.user.xUsername,
        content,
        isTask,
        assigneeXUsername: isTask ? assigneeXUsername : undefined,
        timestamp: new Date()
      });
      
      await message.save();
      
      // Add sender info for real-time display
      const messageWithSender = {
        ...message.toObject(),
        senderProfilePic: socket.user.profilePic
      };
      
      // Broadcast to all users in the project
      io.to(`project-${projectId}`).emit('new-message', messageWithSender);
      
      console.log(`Message sent in project ${projectId} by ${socket.user.xUsername}`);
    } catch (error) {
      console.error('Send message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });
  
  // Typing indicator
  socket.on('typing-start', (projectId) => {
    socket.to(`project-${projectId}`).emit('user-typing', {
      username: socket.user.xUsername,
      isTyping: true
    });
  });
  
  socket.on('typing-stop', (projectId) => {
    socket.to(`project-${projectId}`).emit('user-typing', {
      username: socket.user.xUsername,
      isTyping: false
    });
  });
  
  // Handle disconnection
  socket.on('disconnect', () => {
    if (socket.currentProjectId) {
      socket.to(`project-${socket.currentProjectId}`).emit('user-left', {
        username: socket.user.xUsername
      });
    }
    console.log(`User ${socket.user.xUsername} disconnected from chat`);
  });
});

console.log('✅ WebSocket chat system initialized');

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Enhanced Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // Don't leak error details in production
  const errorMessage = process.env.NODE_ENV === 'production' 
    ? 'Internal Server Error' 
    : err.message;
  
  res.status(err.status || 500).json({ 
    error: errorMessage,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  mongoose.connection.close(() => {
    console.log('MongoDB connection closed.');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  mongoose.connection.close(() => {
    console.log('MongoDB connection closed.');
    process.exit(0);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 CREW Platform Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📖 API Documentation: http://localhost:${PORT}/api-docs`);
  console.log(`💚 Health Check: http://localhost:${PORT}/health`);
  console.log(`💬 WebSocket Chat: Ready for connections`);
});

// Handle server errors
server.on('error', (error) => {
  console.error('Server error:', error);
});

module.exports = app;