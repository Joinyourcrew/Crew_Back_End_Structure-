const mongoose = require('mongoose');

const groupMessageSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
  senderXUsername: { type: String, required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  isTask: { type: Boolean, default: false },
  assigneeXUsername: { type: String },
  completed: { type: Boolean, default: false },
});

module.exports = mongoose.model('GroupMessage', groupMessageSchema);