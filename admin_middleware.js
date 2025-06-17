const User = require('./models/User');
const jwt = require('jsonwebtoken');

// Admin middleware - checks if user is admin
async function verifyAdmin(req, res, next) {
  try {
    const token = req.cookies.jwt || req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret-for-development';
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ xUsername: decoded.xUsername });
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    if (!user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Admin verification error:', error);
    return res.status(401).json({ error: 'Invalid admin token' });
  }
}

module.exports = { verifyAdmin };