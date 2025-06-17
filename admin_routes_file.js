// ADD THESE ROUTES TO YOUR server.js FILE
// Copy and paste these routes into your existing server.js file

const { verifyAdmin } = require('./admin-middleware');
const path = require('path');

// ========== ADMIN ROUTES ==========

// Admin dashboard data endpoint
app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    const User = require('./models/User');
    const Project = require('./models/Project');
    const GroupMessage = require('./models/GroupMessage');

    const [userStats, projectStats, messageStats] = await Promise.all([
      User.aggregate([
        {
          $group: {
            _id: null,
            totalUsers: { $sum: 1 },
            usersWithWallets: { $sum: { $cond: [{ $ne: ['$walletPublicKey', null] }, 1, 0] } },
            recentUsers: {
              $sum: {
                $cond: [
                  { $gte: ['$createdAt', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)] },
                  1,
                  0
                ]
              }
            }
          }
        }
      ]),
      Project.aggregate([
        {
          $group: {
            _id: null,
            totalProjects: { $sum: 1 },
            launchedProjects: { $sum: { $cond: ['$launched', 1, 0] } },
            recentProjects: {
              $sum: {
                $cond: [
                  { $gte: ['$createdAt', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)] },
                  1,
                  0
                ]
              }
            }
          }
        }
      ]),
      GroupMessage.aggregate([
        {
          $group: {
            _id: null,
            totalMessages: { $sum: 1 },
            recentMessages: {
              $sum: {
                $cond: [
                  { $gte: ['$timestamp', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)] },
                  1,
                  0
                ]
              }
            }
          }
        }
      ])
    ]);

    res.json({
      users: userStats[0] || { totalUsers: 0, usersWithWallets: 0, recentUsers: 0 },
      projects: projectStats[0] || { totalProjects: 0, launchedProjects: 0, recentProjects: 0 },
      messages: messageStats[0] || { totalMessages: 0, recentMessages: 0 },
      serverStats: {
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        nodeVersion: process.version,
        environment: process.env.NODE_ENV || 'development'
      }
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ error: 'Failed to load dashboard data' });
  }
});

// Get all users (with pagination)
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const User = require('./models/User');
    const { page = 1, limit = 20, search = '' } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (search) {
      query = {
        $or: [
          { xUsername: { $regex: search, $options: 'i' } },
          { displayName: { $regex: search, $options: 'i' } }
        ]
      };
    }
    
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-encryptedSecretKey -twitterId') // Don't expose sensitive data
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      User.countDocuments(query)
    ]);
    
    res.json({
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get all projects (with pagination)
app.get('/api/admin/projects', verifyAdmin, async (req, res) => {
  try {
    const Project = require('./models/Project');
    const { page = 1, limit = 20, status = 'all' } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (status === 'launched') {
      query.launched = true;
    } else if (status === 'active') {
      query.launched = false;
    }
    
    const [projects, total] = await Promise.all([
      Project.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      Project.countDocuments(query)
    ]);
    
    res.json({
      projects,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// Make user admin
app.post('/api/admin/users/:userId/make-admin', verifyAdmin, async (req, res) => {
  try {
    const User = require('./models/User');
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.isAdmin = true;
    await user.save();
    
    res.json({ message: `${user.xUsername} is now an admin` });
  } catch (error) {
    console.error('Make admin error:', error);
    res.status(500).json({ error: 'Failed to make user admin' });
  }
});

// Remove admin privileges
app.delete('/api/admin/users/:userId/remove-admin', verifyAdmin, async (req, res) => {
  try {
    const User = require('./models/User');
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Don't allow removing admin from yourself
    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ error: 'Cannot remove admin privileges from yourself' });
    }
    
    user.isAdmin = false;
    await user.save();
    
    res.json({ message: `Admin privileges removed from ${user.xUsername}` });
  } catch (error) {
    console.error('Remove admin error:', error);
    res.status(500).json({ error: 'Failed to remove admin privileges' });
  }
});

// Delete project (admin only)
app.delete('/api/admin/projects/:projectId', verifyAdmin, async (req, res) => {
  try {
    const Project = require('./models/Project');
    const GroupMessage = require('./models/GroupMessage');
    
    const project = await Project.findById(req.params.projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // Also delete related messages
    await GroupMessage.deleteMany({ projectId: req.params.projectId });
    await Project.findByIdAndDelete(req.params.projectId);
    
    res.json({ message: `Project "${project.name}" has been deleted` });
  } catch (error) {
    console.error('Delete project error:', error);
    res.status(500).json({ error: 'Failed to delete project' });
  }
});

// Ban/unban user
app.post('/api/admin/users/:userId/ban', verifyAdmin, async (req, res) => {
  try {
    const User = require('./models/User');
    const { reason = 'Banned by admin' } = req.body;
    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.isBanned = true;
    user.banReason = reason;
    user.bannedAt = new Date();
    await user.save();
    
    res.json({ message: `${user.xUsername} has been banned` });
  } catch (error) {
    console.error('Ban user error:', error);
    res.status(500).json({ error: 'Failed to ban user' });
  }
});

app.delete('/api/admin/users/:userId/ban', verifyAdmin, async (req, res) => {
  try {
    const User = require('./models/User');
    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.isBanned = false;
    user.banReason = undefined;
    user.bannedAt = undefined;
    await user.save();
    
    res.json({ message: `${user.xUsername} has been unbanned` });
  } catch (error) {
    console.error('Unban user error:', error);
    res.status(500).json({ error: 'Failed to unban user' });
  }
});

// Seed admin user for initial setup
app.post('/api/admin/seed-admin', async (req, res) => {
  try {
    const User = require('./models/User');
    
    // Only allow this in development or if no admins exist
    const adminCount = await User.countDocuments({ isAdmin: true });
    
    if (process.env.NODE_ENV === 'production' && adminCount > 0) {
      return res.status(403).json({ error: 'Admin already exists' });
    }
    
    const { xUsername } = req.body;
    if (!xUsername) {
      return res.status(400).json({ error: 'Username required' });
    }
    
    const user = await User.findOne({ xUsername });
    if (!user) {
      return res.status(404).json({ error: 'User not found. Please login first.' });
    }
    
    user.isAdmin = true;
    await user.save();
    
    res.json({ 
      message: `${user.xUsername} is now the admin!`,
      user: {
        xUsername: user.xUsername,
        isAdmin: user.isAdmin,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Seed admin error:', error);
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

// System logs (recent activities)
app.get('/api/admin/logs', verifyAdmin, async (req, res) => {
  try {
    const User = require('./models/User');
    const Project = require('./models/Project');
    const GroupMessage = require('./models/GroupMessage');
    
    // Get recent activities across the platform
    const [recentUsers, recentProjects, recentMessages] = await Promise.all([
      User.find()
        .sort({ createdAt: -1 })
        .limit(10)
        .select('xUsername createdAt profilePic'),
      Project.find()
        .sort({ createdAt: -1 })
        .limit(10)
        .select('name creatorXUsername createdAt category'),
      GroupMessage.find()
        .sort({ timestamp: -1 })
        .limit(20)
        .select('senderXUsername content timestamp projectId')
        .populate('projectId', 'name')
    ]);
    
    res.json({
      recentUsers,
      recentProjects, 
      recentMessages
    });
  } catch (error) {
    console.error('Get logs error:', error);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// Serve admin dashboard HTML
app.get('/admin-dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// ========== END ADMIN ROUTES ==========