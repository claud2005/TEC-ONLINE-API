const ClienteSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  morada: { type: String, required: true },
  codigoPostal: { type: String, required: true },
  contacto: { type: String, required: true },
  email: { type: String, required: true },
  contribuinte: { type: String, required: true },
  codigoCliente: { type: String },
  numeroCliente: { type: String }
}, { 
  collection: 'Clientes',
  timestamps: true 
});