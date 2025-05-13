const mongoose = require('mongoose');

const ClienteSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  morada: { type: String, required: true },
  codigoPostal: { type: String, required: true },
  contacto: { type: String, required: true },
  email: { type: String, required: true },
  contribuinte: { type: String, required: true },
  codigoCliente: { type: String, required: true },
  numeroCliente: { type: Number, required: true }
}, { timestamps: true });

module.exports = mongoose.model('Cliente', ClienteSchema);