const mongoose = require('mongoose');

const servicoSchema = new mongoose.Schema({
  numero: { 
    type: String, 
    required: true, 
    unique: true 
  },
  data: { 
    type: Date, 
    required: true 
  },
  status: { 
    type: String, 
    required: true 
  },
  cliente: { 
    type: String, 
    required: true 
  },
  descricao: { 
    type: String, 
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
    type: [String], // Armazena nomes/paths das imagens
    default: []
  }
});

const Servico = mongoose.model('Servico', servicoSchema);
module.exports = Servico;
