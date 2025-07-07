const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { isEmail } = require('validator');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: [true, 'Nome completo é obrigatório'],
    trim: true,
  },
  username: {
    type: String,
    required: [true, 'Nome de usuário é obrigatório'],
    unique: true,
    trim: true,
    minlength: [3, 'Nome de usuário deve ter pelo menos 3 caracteres'],
    maxlength: [20, 'Nome de usuário não pode ter mais de 20 caracteres'],
    match: [/^[a-zA-Z0-9_]+$/, 'Nome de usuário pode conter apenas letras, números e underscores'],
  },
  email: {
    type: String,
    required: [true, 'E-mail é obrigatório'],
    unique: true,
    trim: true,
    lowercase: true,
    validate: [isEmail, 'E-mail inválido'],
  },
  password: {
    type: String,
    required: [true, 'Senha é obrigatória'],
    minlength: [6, 'Senha deve ter pelo menos 6 caracteres'],
  },
  telefone: {
    type: String,
    required: false,
    trim: true,
    match: [/^\+?[0-9\s\-]{7,15}$/, 'Número de telefone inválido'],
    default: '',
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'user',
  },
  profilePicture: {
    type: String,
    default: '',
  },
  bio: {
    type: String,
    default: '',
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
}, { timestamps: true }); // ATIVA createdAt e updatedAt

// Middleware para criptografar senha
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Métodos auxiliares
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generateAuthToken = function () {
  return jwt.sign(
    { userId: this._id, role: this.role },
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '1h' }
  );
};

userSchema.methods.updateProfile = async function (updatedData) {
  if (updatedData.fullName) this.fullName = updatedData.fullName;
  if (updatedData.username) this.username = updatedData.username;
  if (updatedData.bio) this.bio = updatedData.bio;
  if (updatedData.profilePicture) this.profilePicture = updatedData.profilePicture;
  if (updatedData.telefone) this.telefone = updatedData.telefone;
  if (updatedData.role) this.role = updatedData.role;

  await this.save();
  return this;
};

userSchema.methods.generateResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.resetPasswordToken = resetToken;
  this.resetPasswordExpires = Date.now() + 3600000;
  return resetToken;
};

userSchema.methods.isResetPasswordTokenValid = function (token) {
  return this.resetPasswordToken === token && this.resetPasswordExpires > Date.now();
};

const User = mongoose.model('User', userSchema);
module.exports = User;
