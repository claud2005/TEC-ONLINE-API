const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { isEmail } = require('validator');
const crypto = require('crypto');  // Necessário para gerar tokens seguros

// Esquema do Usuário
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
  profilePicture: {
    type: String,
    default: '',
  },
  bio: {  // Adicionando o campo bio, se necessário
    type: String,
    default: '',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

// Criptografar senha antes de salvar no banco de dados
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

// Método para comparar senhas
userSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    return isMatch;
  } catch (err) {
    throw new Error('Erro ao comparar senhas');
  }
};

// Método para gerar um token JWT
userSchema.methods.generateAuthToken = function () {
  const token = jwt.sign(
    { userId: this._id },
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '1h' }
  );
  return token;
};

// Método para atualizar os dados do perfil
userSchema.methods.updateProfile = async function (updatedData) {
  if (updatedData.fullName) {
    this.fullName = updatedData.fullName;
  }

  if (updatedData.username) {
    this.username = updatedData.username;
  }

  if (updatedData.bio) {
    this.bio = updatedData.bio;
  }

  if (updatedData.profilePicture) {
    this.profilePicture = updatedData.profilePicture;
  }

  await this.save();
  return this;
};

// Método para gerar o token de redefinição de senha
userSchema.methods.generateResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex'); // Gera um token de reset único
  this.resetPasswordToken = resetToken;
  this.resetPasswordExpires = Date.now() + 3600000; // Expira em 1 hora
  return resetToken;
};

// Método para verificar se o token de redefinição de senha ainda é válido
userSchema.methods.isResetPasswordTokenValid = function (token) {
  return this.resetPasswordToken === token && this.resetPasswordExpires > Date.now();
};

const User = mongoose.model('User', userSchema);

module.exports = User;
