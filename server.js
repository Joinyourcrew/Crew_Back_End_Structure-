const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const passport = require('passport');
const TwitterStrategy = require('passport-twitter').Strategy;
const session = require('express-session');
const jwt = require('jsonwebtoken');
const { Keypair } = require('@solana/web3.js');
const crypto = require('crypto');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret',
  resave: false,
  saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  xUsername: { type: String, required: true, unique: true },
  profilePic: { type: String },
  walletPublicKey: { type: String },
  encryptedSecretKey: { type: String },
  twitterId: { type: String, required: true, unique: true },
});
const User = mongoose.model('User', userSchema);

const projectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  creatorXUsername: { type: String, required: true },
  creatorProfilePic: { type: String },
  summary: { type: String, required: true },
  neededPositions: [{ type: String, required: true }],
  acceptedMembers: [{ xUsername: String, position: String }],
  checklist: {
    socials: { completed: { type: Boolean, default: false }, link: String },
    github: { completed: { type: Boolean, default: false }, link: String },
    rewardFee: { 
      completed: { type: Boolean, default: false }, 
      greenlights: { type: Map, of: Number },
      total: { type: Number, default: 0 }
    },
    whitepaper: { completed: { type: Boolean, default: false }, link: String },
    tokenomics: { completed: { type: Boolean, default: false }, link: String },
    website: { completed: { type: Boolean, default: false }, link: String },
  },
  launched: { type: Boolean, default: false },
  launchDate: { type: Date },
  score: { type: Number, default: 0 },
  marketCap: { type: String },
  volume: { type: String },
  tokenChartPoints: { type: String },
  link: { type: String, default: 'https://x.com' },
});
const Project = mongoose.model('Project', projectSchema);

const messageSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  projectName: { type: String, required: true },
  applicantXUsername: { type: String, required: true },
  position: { type: String, required: true },
  experience: { type: String, required: true },
  recipientXUsername: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
  type: { type: String, default: 'application' },
  walletPublicKey: { type: String },
});
const Message = mongoose.model('Message', messageSchema);

const groupMessageSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  senderXUsername: { type: String, required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  isTask: { type: Boolean, default: false },
  assigneeXUsername: { type: String },
  completed: { type: Boolean, default: false },
});
const GroupMessage = mongoose.model('GroupMessage', groupMessageSchema);

passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_CONSUMER_KEY,
  consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
  callbackURL: 'http://localhost:5000/auth/x/callback',
}, async (token, tokenSecret, profile, done) => {
  try {
    let user = await User.findOne({ twitterId: profile.id });
    if (!user) {
      user = new User({
        twitterId: profile.id,
        xUsername: profile.username,
        profilePic: profile.photos[0]?.value || 'https://via.placeholder.com/50',
      });
      await user.save();
    }
    done(null, user);
  } catch (error) {
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
    done(error);
  }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

function encryptSecretKey(secretKey, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(secretKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encrypted: encrypted };
}

async function generateAndStoreWallet(user) {
  if (user.walletPublicKey) return { publicKey: user.walletPublicKey };
  const keypair = Keypair.generate();
  const publicKey = keypair.publicKey.toString();
  const secretKey = Buffer.from(keypair.secretKey).toString('hex');
  const { iv, encrypted } = encryptSecretKey(secretKey, ENCRYPTION_KEY);
  user.walletPublicKey = publicKey;
  user.encryptedSecretKey = JSON.stringify({ iv, encrypted });
  await user.save();
  return { publicKey };
}

async function verifyXToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findOne({ xUsername: decoded.xUsername });
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/auth/x', passport.authenticate('twitter'));

app.get('/auth/x/callback', passport.authenticate('twitter', { failureRedirect: '/signup.html' }), (req, res) => {
  const token = jwt.sign({ xUsername: req.user.xUsername }, JWT_SECRET, { expiresIn: '1h' });
  res.redirect(`/signup.html?token=${token}`);
});

app.post('/api/projects', verifyXToken, async (req, res) => {
  const { name, summary, neededPositions } = req.body;
  try {
    const { publicKey } = await generateAndStoreWallet(req.user);
    const project = new Project({
      name,
      creatorXUsername: req.user.xUsername,
      creatorProfilePic: req.user.profilePic,
      summary,
      neededPositions,
      acceptedMembers: [{ xUsername: req.user.xUsername, position: 'Creator' }],
      link: `https://x.com/${req.user.xUsername}/status/${Date.now()}`,
    });
    await project.save();
    const message = new Message({
      projectId: project._id,
      projectName: project.name,
      applicantXUsername: req.user.xUsername,
      recipientXUsername: req.user.xUsername,
      type: 'wallet',
      walletPublicKey: publicKey,
      position: 'N/A',
      experience: `Your Solana wallet has been created. Public Key: ${publicKey}`,
    });
    await message.save();
    res.status(201).json({ project, walletPublicKey: publicKey });
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ error: 'Failed to create project' });
  }
});

app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find({ launched: false });
    res.json(projects);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

app.get('/api/projects/user', verifyXToken, async (req, res) => {
  try {
    const projects = await Project.find({
      $or: [
        { creatorXUsername: req.user.xUsername },
        { 'acceptedMembers.xUsername': req.user.xUsername }
      ]
    });
    res.json(projects);
  } catch (error) {
    console.error('Error fetching user projects:', error);
    res.status(500).json({ error: 'Failed to fetch user projects' });
  }
});

app.get('/api/projects/:id', verifyXToken, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project || (!project.acceptedMembers.some(m => m.xUsername === req.user.xUsername) && 
                     project.creatorXUsername !== req.user.xUsername)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    res.json(project);
  } catch (error) {
    console.error('Error fetching project:', error);
    res.status(500).json({ error: 'Failed to fetch project' });
  }
});

app.get('/api/projects/top', async (req, res) => {
  try {
    const projects = await Project.find({ launched: true })
      .sort({ score: -1 })
      .limit(3);
    res.json(projects);
  } catch (error) {
    console.error('Error fetching top projects:', error);
    res.status(500).json({ error: 'Failed to fetch top projects' });
  }
});

app.post('/api/projects/apply', verifyXToken, async (req, res) => {
  const { projectId, position, experience } = req.body;
  try {
    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (project.acceptedMembers.length >= project.neededPositions.length) {
      return res.status(400).json({ error: 'Project is fully staffed' });
    }
    const message = new Message({
      projectId,
      projectName: project.name,
      applicantXUsername: req.user.xUsername,
      position,
      experience,
      recipientXUsername: project.creatorXUsername,
    });
    await message.save();
    res.status(201).json({ message: 'Application submitted', link: project.link });
  } catch (error) {
    console.error('Error submitting application:', error);
    res.status(500).json({ error: 'Failed to submit application' });
  }
});

app.post('/api/projects/accept', verifyXToken, async (req, res) => {
  const { messageId } = req.body;
  try {
    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ error: 'Message not found' });
    if (message.recipientXUsername !== req.user.xUsername) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const project = await Project.findById(message.projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (project.acceptedMembers.length >= project.neededPositions.length) {
      return res.status(400).json({ error: 'Project is fully staffed' });
    }
    const applicant = await User.findOne({ xUsername: message.applicantXUsername });
    if (!applicant) return res.status(404).json({ error: 'Applicant not found' });
    if (project.acceptedMembers.some(m => m.xUsername === applicant.xUsername)) {
      return res.status(400).json({ error: 'User already accepted' });
    }
    const { publicKey } = await generateAndStoreWallet(applicant);
    project.acceptedMembers.push({ xUsername: applicant.xUsername, position: message.position });
    await project.save();
    const walletMessage = new Message({
      projectId: message.projectId,
      projectName: message.projectName,
      applicantXUsername: 'System',
      recipientXUsername: applicant.xUsername,
      type: 'wallet',
      walletPublicKey: publicKey,
      position: message.position,
      experience: `You have been approved for ${message.projectName}! Your Solana wallet public key: ${publicKey}`,
    });
    await walletMessage.save();
    const groupMessage = new GroupMessage({
      projectId: message.projectId,
      senderXUsername: 'System',
      content: `@${applicant.xUsername} has joined the project as ${message.position}!`,
    });
    await groupMessage.save();
    message.read = true;
    await message.save();
    res.json({ message: 'Applicant accepted and wallet created', walletPublicKey: publicKey });
  } catch (error) {
    console.error('Error accepting application:', error);
    res.status(500).json({ error: 'Failed to accept application' });
  }
});

app.post('/api/projects/:id/checklist/:item', verifyXToken, async (req, res) => {
  const { id, item } = req.params;
  const { link } = req.body;
  try {
    const project = await Project.findById(id);
    if (!project || (!project.acceptedMembers.some(m => m.xUsername === req.user.xUsername) && 
                     project.creatorXUsername !== req.user.xUsername)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    if (!['socials', 'github', 'whitepaper', 'tokenomics', 'website'].includes(item)) {
      return res.status(400).json({ error: 'Invalid checklist item' });
    }
    if (!link || !/^https?:\/\//.test(link)) {
      return res.status(400).json({ error: 'Invalid URL' });
    }
    project.checklist[item].link = link;
    project.checklist[item].completed = true;
    await project.save();
    const groupMessage = new GroupMessage({
      projectId: id,
      senderXUsername: 'System',
      content: `@${req.user.xUsername} completed checklist item: ${item} with link ${link}`,
    });
    await groupMessage.save();
    res.json({ message: 'Checklist item updated' });
  } catch (error) {
    console.error('Error updating checklist:', error);
    res.status(500).json({ error: 'Failed to update checklist' });
  }
});

app.post('/api/projects/:id/checklist/reward-fee', verifyXToken, async (req, res) => {
  const { id } = req.params;
  const { share } = req.body;
  try {
    const project = await Project.findById(id);
    if (!project || (!project.acceptedMembers.some(m => m.xUsername === req.user.xUsername) && 
                     project.creatorXUsername !== req.user.xUsername)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    if (isNaN(share) || share <= 0 || share > 100) {
      return res.status(400).json({ error: 'Invalid share percentage' });
    }
    project.checklist.rewardFee.greenlights.set(req.user.xUsername, share);
    const total = Array.from(project.checklist.rewardFee.greenlights.values()).reduce((sum, s) => sum + s, 0);
    project.checklist.rewardFee.total = total;
    const memberCount = project.acceptedMembers.length + 1;
    project.checklist.rewardFee.completed = project.checklist.rewardFee.greenlights.size === memberCount && Math.abs(total - 100) < 0.01;
    await project.save();
    if (project.checklist.rewardFee.completed) {
      const groupMessage = new GroupMessage({
        projectId: id,
        senderXUsername: 'System',
        content: `Reward fee split finalized: ${Array.from(project.checklist.rewardFee.greenlights.entries())
          .map(([user, s]) => `@${user}: ${s}%`).join(', ')}`,
      });
      await groupMessage.save();
    }
    res.json({ message: 'Reward fee greenlit' });
  } catch (error) {
    console.error('Error greenlighting reward fee:', error);
    res.status(500).json({ error: 'Failed to greenlight reward fee' });
  }
});

app.post('/api/projects/:id/launch', verifyXToken, async (req, res) => {
  const { id } = req.params;
  try {
    const project = await Project.findById(id);
    if (!project || project.creatorXUsername !== req.user.xUsername) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const allCompleted = Object.values(project.checklist).every(item => item.completed);
    if (!allCompleted) {
      return res.status(400).json({ error: 'Checklist not complete' });
    }
    project.launched = true;
    project.launchDate = new Date();
    await project.save();
    const groupMessage = new GroupMessage({
      projectId: id,
      senderXUsername: 'System',
      content: `Project ${project.name} has launched!`,
    });
    await groupMessage.save();
    res.json({ message: 'Project launched' });
  } catch (error) {
    console.error('Error launching project:', error);
    res.status(500).json({ error: 'Failed to launch project' });
  }
});

app.post('/api/group-messages/:projectId', verifyXToken, async (req, res) => {
  const { projectId } = req.params;
  const { content, assigneeXUsername } = req.body;
  try {
    const project = await Project.findById(projectId);
    if (!project || (!project.acceptedMembers.some(m => m.xUsername === req.user.xUsername) && 
                     project.creatorXUsername !== req.user.xUsername)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    if (assigneeXUsername && !project.acceptedMembers.some(m => m.xUsername === assigneeXUsername) && 
        project.creatorXUsername !== assigneeXUsername) {
      return res.status(400).json({ error: 'Invalid assignee' });
    }
    const groupMessage = new GroupMessage({
      projectId,
      senderXUsername: req.user.xUsername,
      content,
      isTask: !!assigneeXUsername,
      assigneeXUsername,
    });
    await groupMessage.save();
    res.json({ message: 'Message sent' });
  } catch (error) {
    console.error('Error sending group message:', error);
    res.status(500).json({ error: 'Failed to send group message' });
  }
});

app.get('/api/group-messages/:projectId', verifyXToken, async (req, res) => {
  const { projectId } = req.params;
  try {
    const project = await Project.findById(projectId);
    if (!project || (!project.acceptedMembers.some(m => m.xUsername === req.user.xUsername) && 
                     project.creatorXUsername !== req.user.xUsername)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const messages = await GroupMessage.find({ projectId }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (error) {
    console.error('Error fetching group messages:', error);
    res.status(500).json({ error: 'Failed to fetch group messages' });
  }
});

app.post('/api/group-messages/:messageId/complete', verifyXToken, async (req, res) => {
  const { messageId } = req.params;
  try {
    const message = await GroupMessage.findById(messageId);
    if (!message || message.assigneeXUsername !== req.user.xUsername) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    message.completed = true;
    await message.save();
    const project = await Project.findById(message.projectId);
    const groupMessage = new GroupMessage({
      projectId: message.projectId,
      senderXUsername: 'System',
      content: `@${req.user.xUsername} completed task: ${message.content}`,
    });
    await groupMessage.save();
    res.json({ message: 'Task marked complete' });
  } catch (error) {
    console.error('Error marking task complete:', error);
    res.status(500).json({ error: 'Failed to mark task complete' });
  }
});

app.get('/api/messages', verifyXToken, async (req, res) => {
  try {
    const messages = await Message.find({ recipientXUsername: req.user.xUsername })
      .sort({ timestamp: -1 });
    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.get('/api/messages/unread', verifyXToken, async (req, res) => {
  try {
    const count = await Message.countDocuments({ 
      recipientXUsername: req.user.xUsername, 
      read: false 
    });
    res.json({ count });
  } catch (error) {
    console.error('Error fetching unread message count:', error);
    res.status(500).json({ error: 'Failed to fetch unread message count' });
  }
});

app.get('/api/wallet', verifyXToken, async (req, res) => {
  try {
    if (!req.user.walletPublicKey) {
      return res.status(404).json({ error: 'No wallet found' });
    }
    res.json({ publicKey: req.user.walletPublicKey });
  } catch (error) {
    console.error('Error fetching wallet:', error);
    res.status(500).json({ error: 'Failed to fetch wallet' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));