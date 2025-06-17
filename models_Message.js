const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
  projectName: { type: String, required: true },
  applicantXUsername: { type: String, required: true },
  position: { type: String, required: true },
  experience: { type: String, required: true },
  recipientXUsername: { type: String, required: true, index: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
  type: { type: String, default: 'application' },
  walletPublicKey: { type: String },
});

module.exports = mongoose.model('Message', messageSchema);