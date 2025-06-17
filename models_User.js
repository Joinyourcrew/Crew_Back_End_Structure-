const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  xUsername: { type: String, required: true, unique: true, index: true },
  profilePic: { type: String },
  walletPublicKey: { type: String },
  encryptedSecretKey: { type: String },
  twitterId: { type: String, required: true, unique: true, index: true },
});

module.exports = mongoose.model('User', userSchema);