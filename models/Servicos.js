const mongoose = require('mongoose');

const servicoSchema = new mongoose.Schema({
  numero: { 
    type: String, 
    required: true, 
    unique: true 
  },
  dataServico: { 
    type: String,   // Ex.: '2025-06-16'
    required: true 
  },
  horaServico: { 
    type: String,   // Ex.: '14:30'
    required: true 
  },
  status: { 
    type: String, 
    required: true 
  },
  cliente: { 
    type: mongoose.Schema.Types.ObjectId, // Alterado para ObjectId
    ref: 'Cliente', // Referência ao modelo Cliente
    required: true 
  },
  responsavel: { 
    type: String, 
    required: true 
  },
  observacoes: { 
    type: String, 
    required: true 
  },
  autorServico: { 
    type: String, 
    required: true 
  },
  nomeCompletoCliente: { 
    type: String, 
    required: true 
  },
  codigoPostalCliente: { 
    type: String, 
    required: false 
  },
  contatoCliente: { 
    type: String, 
    required: true 
  },
  modeloAparelho: { 
    type: String, 
    required: true 
  },
  marcaAparelho: { 
    type: String, 
    required: true 
  },
  problemaRelatado: { 
    type: String, 
    required: true 
  },
  solucaoInicial: { 
    type: String, 
    required: true 
  },
  valorTotal: { 
    type: Number, 
    required: true 
  },
  imagens: {
    type: [String], 
    default: [],
    required: false
  }
}, { timestamps: true });

const Servico = mongoose.model('Servico', servicoSchema);
module.exports = Servico;