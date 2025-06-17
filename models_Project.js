// Updated models/Project.js - Add this to your existing model

const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  creatorXUsername: { type: String, required: true, index: true },
  creatorProfilePic: { type: String },
  summary: { type: String, required: true },
  
  // Add category field for filtering
  category: { 
    type: String, 
    enum: ['defi', 'nft', 'gaming', 'dao', 'infrastructure', 'social', 'other'],
    default: 'other'
  },
  
  // Add timeline and experience level
  timeline: {
    type: String,
    enum: ['1-3 months', '3-6 months', '6-12 months', '1+ years', 'ongoing']
  },
  experienceLevel: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced', 'mixed']
  },
  
  neededPositions: [{ type: String, required: true }],
  acceptedMembers: [{ xUsername: String, position: String }],
  
  // Enhanced checklist for Web3 projects
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
    
    // Add Web3-specific checklist items
    smartContract: { completed: { type: Boolean, default: false }, link: String },
    audit: { completed: { type: Boolean, default: false }, link: String },
    testnet: { completed: { type: Boolean, default: false }, link: String },
    mainnet: { completed: { type: Boolean, default: false }, link: String }
  },
  
  // Project status
  launched: { type: Boolean, default: false },
  launchDate: { type: Date },
  
  // Add development stage
  developmentStage: {
    type: String,
    enum: ['idea', 'mvp', 'testnet', 'mainnet'],
    default: 'idea'
  },
  
  // Metrics for launched projects
  score: { type: Number, default: 0 },
  marketCap: { type: String },
  volume: { type: String },
  tokenPrice: { type: String },
  priceChange24h: { type: String },
  
  // Chart data (JSON string of price points)
  tokenChartPoints: { type: String },
  
  // Additional fields
  link: { type: String, default: 'https://x.com' },
  
  // Goals and success metrics
  successMetrics: { type: String },
  
  // Skills/roles needed (enhanced)
  skillsNeeded: [{ type: String }],
  
  // Additional info
  additionalInfo: { type: String },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Add index for better query performance
projectSchema.index({ launched: 1, score: -1 });
projectSchema.index({ category: 1, launched: 1 });
projectSchema.index({ creatorXUsername: 1 });
projectSchema.index({ developmentStage: 1 });

// Update the updatedAt field on save
projectSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Project', projectSchema);