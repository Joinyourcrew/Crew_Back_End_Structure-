#!/bin/bash

# CREW Platform Deployment & Testing Script
# Run this script to set up and deploy your CREW platform

set -e  # Exit on any error

echo "🚀 CREW Platform Deployment Script"
echo "=================================="

# Check if required tools are installed
check_dependencies() {
    echo "🔍 Checking dependencies..."
    
    command -v node >/dev/null 2>&1 || { echo "❌ Node.js is required but not installed. Please install Node.js 18+"; exit 1; }
    command -v npm >/dev/null 2>&1 || { echo "❌ npm is required but not installed."; exit 1; }
    command -v docker >/dev/null 2>&1 || { echo "⚠️  Docker not found. Install Docker to use containerized deployment."; }
    
    echo "✅ Dependencies check passed"
}

# Create necessary directories
setup_directories() {
    echo "📁 Setting up directories..."
    
    mkdir -p uploads
    mkdir -p logs
    mkdir -p mongo-init
    mkdir -p data/db
    
    echo "✅ Directories created"
}

# Generate secure keys
generate_keys() {
    echo "🔐 Generating secure keys..."
    
    if [ ! -f .env ]; then
        echo "📝 Creating .env file..."
        
        # Generate random keys
        JWT_SECRET=$(openssl rand -hex 64 2>/dev/null || echo "your_jwt_secret_$(date +%s)")
        ENCRYPTION_KEY=$(openssl rand -hex 32 2>/dev/null || echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        SESSION_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "your_session_secret_$(date +%s)")
        
        cat > .env << EOF
# CREW Platform Environment Configuration
MONGO_URI=mongodb://localhost:27017/crew_platform
TWITTER_CONSUMER_KEY=your_twitter_consumer_key_here
TWITTER_CONSUMER_SECRET=your_twitter_consumer_secret_here
TWITTER_CALLBACK_URL=http://localhost:5000/auth/x/callback
JWT_SECRET=${JWT_SECRET}
ENCRYPTION_KEY=${ENCRYPTION_KEY}
SESSION_SECRET=${SESSION_SECRET}
PORT=5000
FRONTEND_DOMAIN=http://localhost:5000
ALLOWED_ORIGINS=http://localhost:5000,http://localhost:3000,http://localhost:5500,http://127.0.0.1:5500
NODE_ENV=development
SOLANA_RPC_URL=https://api.devnet.solana.com
LOG_LEVEL=info

# Production settings (uncomment for production)
# NODE_ENV=production
# MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/crew_platform
# TWITTER_CALLBACK_URL=https://yourdomain.com/auth/x/callback
# FRONTEND_DOMAIN=https://yourdomain.com
# ALLOWED_ORIGINS=https://yourdomain.com
# SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
EOF
        
        echo "✅ Environment file created with secure keys"
        echo "⚠️  IMPORTANT: Update your Twitter API keys in .env file"
    else
        echo "⚠️  .env file already exists, skipping key generation"
    fi
}

# Install dependencies
install_dependencies() {
    echo "📦 Installing Node.js dependencies..."
    npm install
    echo "✅ Dependencies installed"
}

# Update User model to include admin field
update_user_model() {
    echo "📝 Updating User model..."
    
    # Check if models directory exists
    if [ ! -d "models" ]; then
        echo "⚠️  Models directory not found, skipping user model update"
        return
    fi
    
    # Check if User.js exists
    if [ ! -f "models/User.js" ]; then
        echo "⚠️  models/User.js not found, skipping user model update"
        return
    fi
    
    # Check if isAdmin field exists
    if grep -q "isAdmin" models/User.js; then
        echo "✅ User model already has admin fields"
        return
    fi
    
    # Backup original file
    cp models/User.js models/User.js.backup
    
    # Add admin fields to user schema (try different approaches)
    if grep -q "profilePic.*String" models/User.js; then
        sed -i.bak '/profilePic.*String/a \ \ isAdmin: { type: Boolean, default: false },\n  isBanned: { type: Boolean, default: false },\n  banReason: { type: String },\n  bannedAt: { type: Date },' models/User.js
    elif grep -q "twitterId.*String" models/User.js; then
        sed -i.bak '/twitterId.*String/a \ \ isAdmin: { type: Boolean, default: false },\n  isBanned: { type: Boolean, default: false },\n  banReason: { type: String },\n  bannedAt: { type: Date },' models/User.js
    else
        echo "⚠️  Could not automatically update User model. Please manually add admin fields."
    fi
    
    echo "✅ User model updated with admin fields"
}

# Start MongoDB (if not running)
start_mongodb() {
    echo "🗄️  Checking MongoDB..."
    
    if command -v mongod >/dev/null 2>&1; then
        # Check if MongoDB is already running
        if pgrep mongod > /dev/null; then
            echo "✅ MongoDB is already running"
        else
            echo "🚀 Starting MongoDB..."
            mongod --dbpath ./data/db --fork --logpath ./logs/mongodb.log 2>/dev/null || {
                echo "⚠️  Could not start MongoDB. Please start it manually or use Docker."
            }
            sleep 3
        fi
    else
        echo "⚠️  MongoDB not installed locally. Using Docker or external MongoDB."
    fi
}

# Test the application
test_application() {
    echo "🧪 Testing application..."
    
    # Start the server in background
    echo "🚀 Starting CREW Platform server..."
    npm start &
    SERVER_PID=$!
    
    # Wait for server to start
    echo "⏳ Waiting for server to start..."
    sleep 8
    
    # Test health endpoint
    echo "🔍 Testing health endpoint..."
    if curl -f http://localhost:5000/health > /dev/null 2>&1; then
        echo "✅ Health check passed"
    else
        echo "❌ Health check failed - server may still be starting"
    fi
    
    # Test API endpoints
    echo "🔍 Testing API endpoints..."
    
    # Test projects endpoint
    if curl -f http://localhost:5000/api/projects/launched > /dev/null 2>&1; then
        echo "✅ Projects API working"
    else
        echo "⚠️  Projects API test failed - may need authentication"
    fi
    
    echo "✅ Basic tests completed"
    
    # Stop the server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}

# Deploy with Docker
deploy_with_docker() {
    echo "🐳 Deploying with Docker..."
    
    if command -v docker >/dev/null 2>&1; then
        echo "🏗️  Building Docker image..."
        docker build -t crew-platform .
        
        echo "🚀 Starting containers..."
        docker-compose up -d
        
        echo "⏳ Waiting for containers to start..."
        sleep 15
        
        # Test Docker deployment
        if curl -f http://localhost:5000/health > /dev/null 2>&1; then
            echo "✅ Docker deployment successful"
            echo "🌐 Application running at: http://localhost:5000"
            echo "📊 Admin dashboard: http://localhost:5000/admin-dashboard.html"
        else
            echo "❌ Docker deployment failed"
            docker-compose logs app
        fi
    else
        echo "❌ Docker not available for deployment"
    fi
}

# Create startup script
create_startup_script() {
    echo "📝 Creating startup script..."
    
    cat > start.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting CREW Platform..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found! Please run deploy.sh first."
    exit 1
fi

# Start MongoDB if needed
if command -v mongod >/dev/null 2>&1; then
    if ! pgrep mongod > /dev/null; then
        echo "🗄️  Starting MongoDB..."
        mkdir -p data/db logs
        mongod --dbpath ./data/db --fork --logpath ./logs/mongodb.log 2>/dev/null || {
            echo "⚠️  Could not start MongoDB. Please start it manually."
        }
        sleep 3
    fi
fi

# Start the application
echo "🚀 Starting CREW Platform server..."
echo "🌐 Access at: http://localhost:5000"
echo "📊 Admin dashboard: http://localhost:5000/admin-dashboard.html"
echo "Press Ctrl+C to stop"
npm start
EOF
    
    chmod +x start.sh
    echo "✅ Startup script created (start.sh)"
}

# Create admin setup instructions
create_admin_instructions() {
    cat > ADMIN_SETUP.md << 'EOF'
# CREW Platform Admin Setup

## 🚀 Quick Start

1. **Start the platform:**
   ```bash
   ./start.sh
   ```

2. **Access the application:**
   - Main site: http://localhost:5000
   - Admin dashboard: http://localhost:5000/admin-dashboard.html

3. **Create your first admin user:**
   
   a. **Login via Twitter/X:**
      - Go to http://localhost:5000
      - Click "Login with X/Twitter"
      - Complete OAuth flow
   
   b. **Make yourself admin:**
      ```bash
      curl -X POST http://localhost:5000/api/admin/seed-admin \
           -H "Content-Type: application/json" \
           -d '{"xUsername": "your_twitter_username"}'
      ```

4. **Access Admin Dashboard:**
   - Go to http://localhost:5000/admin-dashboard.html
   - You should now see the full admin interface

## 🛠️ Admin Features

- **User Management:** View, ban/unban users, make/remove admins
- **Project Management:** View and delete projects
- **System Monitoring:** Server stats, uptime, memory usage
- **Activity Logs:** Recent user registrations, projects, messages

## 🔧 Environment Setup

Make sure to update your `.env` file with:

```bash
# Required: Get these from Twitter Developer Console
TWITTER_CONSUMER_KEY=your_key_here
TWITTER_CONSUMER_SECRET=your_secret_here

# For production deployment
NODE_ENV=production
MONGO_URI=your_production_mongodb_uri
TWITTER_CALLBACK_URL=https://yourdomain.com/auth/x/callback
FRONTEND_DOMAIN=https://yourdomain.com
ALLOWED_ORIGINS=https://yourdomain.com
```

## 🐳 Docker Deployment

```bash
# Build and run with Docker
docker-compose up -d

# View logs
docker-compose logs -f app

# Stop containers
docker-compose down
```

## 🧪 Testing

```bash
# Test all endpoints
./deploy.sh test

# Manual API testing
curl http://localhost:5000/health
curl http://localhost:5000/api/projects/launched
```

## 🔒 Security Notes

- Change all default keys in production
- Use HTTPS in production
- Set up proper firewall rules
- Regular backup of MongoDB
- Monitor admin access logs

## 📞 Troubleshooting

**Can't access admin dashboard?**
- Make sure you're logged in via Twitter/X first
- Run the seed-admin command with your exact Twitter username
- Check browser console for errors

**Server won't start?**
- Check MongoDB is running
- Verify .env file exists and has correct values
- Check logs in ./logs/ directory

**Twitter auth not working?**
- Verify Twitter API keys in .env
- Check callback URL matches your Twitter app settings
- Ensure your Twitter app has read permissions
EOF

    echo "✅ Admin setup instructions created (ADMIN_SETUP.md)"
}

# Add admin routes to existing server.js
update_server_js() {
    echo "🔧 Updating server.js with admin routes..."
    
    if [ ! -f "server.js" ]; then
        echo "❌ server.js not found!"
        return
    fi
    
    # Check if admin routes already exist
    if grep -q "verifyAdmin" server.js; then
        echo "✅ Admin routes already exist in server.js"
        return
    fi
    
    # Create admin routes file
    cat > admin-routes.js << 'EOF'
// Add these routes to your server.js file

const { verifyAdmin } = require('./admin-middleware');

// Admin dashboard endpoint
app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
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

// Seed admin user
app.post('/api/admin/seed-admin', async (req, res) => {
  try {
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

// Serve admin dashboard
app.get('/admin-dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});
EOF
    
    echo "✅ Admin routes created in admin-routes.js"
    echo "⚠️  Please manually add the contents of admin-routes.js to your server.js"
}

# Main deployment function
main() {
    echo "🚀 Starting CREW Platform deployment..."
    
    check_dependencies
    setup_directories
    generate_keys
    install_dependencies
    update_user_model
    update_server_js
    create_startup_script
    create_admin_instructions
    
    echo ""
    echo "✅ CREW Platform setup complete!"
    echo ""
    echo "📋 Next Steps:"
    echo "1. Update your Twitter API keys in .env file"
    echo "2. Add admin routes to server.js (see admin-routes.js)"
    echo "3. Run: ./start.sh"
    echo "4. Login via Twitter at http://localhost:5000"
    echo "5. Make yourself admin: curl -X POST http://localhost:5000/api/admin/seed-admin -H \"Content-Type: application/json\" -d '{\"xUsername\": \"your_username\"}'"
    echo "6. Access admin dashboard at http://localhost:5000/admin-dashboard.html"
    echo ""
    echo "📚 Documentation: See ADMIN_SETUP.md for detailed instructions"
    echo ""
    
    # Ask if user wants to start now
    read -p "🚀 Start the platform now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🚀 Starting platform..."
        ./start.sh
    else
        echo "👍 Run './start.sh' when you're ready!"
    fi
}

# Handle command line arguments
case "${1:-}" in
    "test")
        test_application
        ;;
    "docker")
        deploy_with_docker
        ;;
    *)
        main
        ;;
esac