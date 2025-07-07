const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator'); // Para validação de dados
const multer = require('multer'); // Importando o multer para manipulação de arquivos
const path = require('path');
const fs = require('fs'); // Importando o fs para verificar e criar a pasta
const crypto = require('crypto');
const nodemailer = require('nodemailer');
dotenv.config();

const User = require('./models/User');
const Servico = require('./models/Servicos'); 
const Cliente = require('./models/Cliente'); 

const app = express();

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Conexão com o MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://TECONLINE:claudio654321@cluster0.1mpg6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Conectado ao MongoDB');
})
.catch((err) => {
  console.error('❌ Erro ao conectar ao MongoDB:', err);
  process.exit(1);
});

// Middleware para tratamento de erros
const errorHandler = (err, req, res, next) => {
  console.error('Erro:', err);
  res.status(500).json({ message: 'Erro interno no servidor', error: err.message });
};

app.use(errorHandler);

// Middleware para autenticar o token JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Token não fornecido' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido ou expirado' });
    }
    req.user = decoded;
    next();
  });
};

// Configuração do multer para armazenamento de imagem
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Diretório para armazenar as imagens
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext); // Definir um nome único para o arquivo
  },
});

const upload = multer({ storage });

app.use(express.json());  // Middleware para interpretar JSON no corpo da requisição

// Rota para registrar um novo utilizador
app.post('/api/signup', [
  body('fullName').notEmpty().withMessage('Nome completo é obrigatório'),
  body('username').notEmpty().withMessage('Nome de usuário é obrigatório'),
  body('email').isEmail().withMessage('E-mail inválido'),
  body('password').isLength({ min: 6 }).withMessage('A senha deve ter pelo menos 6 caracteres'),
  body('telefone').optional().isString().withMessage('Telefone inválido').trim(),
  body('role').optional().isIn(['user', 'admin']).withMessage('Tipo de utilizador inválido'),
], async (req, res, next) => {
  console.log('req.body:', req.body);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { fullName, username, email, password, telefone, role = 'user' } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Usuário ou e-mail já cadastrados' });
    }

    const newUser = new User({ fullName, username, email, password, telefone, role });
    await newUser.save();

    return res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    next(error);
  }
});


// Rota para buscar todos os usuários
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password'); // Exclui a senha dos resultados
    res.status(200).json(users);
  } catch (error) {
    console.error('Erro ao buscar usuários:', error);
    res.status(500).json({ message: 'Erro ao buscar usuários' });
  }
});

// Rota para atualizar um utilizador existente
app.put('/api/users/:id', [
  body('fullName').notEmpty().withMessage('Nome completo é obrigatório'),
  body('username').notEmpty().withMessage('Nome de usuário é obrigatório'),
  body('email').isEmail().withMessage('E-mail inválido'),
  body('telefone').optional().isString().withMessage('Telefone inválido').trim(),
  body('password').optional().isLength({ min: 6 }).withMessage('A senha deve ter pelo menos 6 caracteres'),
  body('role').optional().isIn(['user', 'admin']).withMessage('Tipo de utilizador inválido'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const userId = req.params.id;
    const updateData = { 
      ...req.body,
      updatedAt: new Date() // Garante que o campo updatedAt será sempre atualizado
    };

    // Remove a senha do updateData se estiver vazia ou não for fornecida
    if (!updateData.password || updateData.password.trim() === '') {
      delete updateData.password;
    } else {
      // Se uma nova senha foi fornecida, ela será hasheada pelo pre('save') hook
      updateData.password = updateData.password.trim();
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId, 
      updateData, 
      {
        new: true,          // Retorna o documento atualizado
        runValidators: true, // Executa as validações do schema
        context: 'query'     // Necessário para algumas validações do Mongoose
      }
    ).select('-password -__v'); // Exclui a senha e a versão do documento

    if (!updatedUser) {
      return res.status(404).json({ message: 'Utilizador não encontrado' });
    }

    // Log para debug (pode remover em produção)
    console.log('Utilizador atualizado:', {
      id: updatedUser._id,
      nome: updatedUser.fullName,
      atualizadoEm: updatedUser.updatedAt
    });

    res.status(200).json({ 
      message: 'Utilizador atualizado com sucesso!', 
      user: updatedUser 
    });
  } catch (error) {
    console.error('Erro ao atualizar utilizador:', error);
    
    // Tratamento de erros mais específico
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        message: 'Erro de validação',
        details: error.message 
      });
    }
    
    if (error.code === 11000) {
      return res.status(400).json({ 
        message: 'Email ou nome de usuário já existe' 
      });
    }
    
    res.status(500).json({ 
      message: 'Erro ao atualizar utilizador',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Rota para eliminar um utilizador
app.delete('/api/users/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    const deletedUser = await User.findByIdAndDelete(userId);

    if (!deletedUser) {
      return res.status(404).json({ message: 'Utilizador não encontrado' });
    }

    res.status(200).json({ message: 'Utilizador excluído com sucesso!' });
  } catch (error) {
    console.error('Erro ao excluir utilizador:', error);
    res.status(500).json({ message: 'Erro ao excluir utilizador' });
  }
});


// Rota para buscar 1 utilizador pelo ID
app.get('/api/users/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await User.findById(userId).select('-password'); // Excluir senha na resposta

    if (!user) {
      return res.status(404).json({ message: 'Utilizador não encontrado' });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error('Erro ao buscar utilizador:', error);
    res.status(500).json({ message: 'Erro ao buscar utilizador' });
  }
});


// ✅ ROTA: Admin altera senha de qualquer utilizador
app.put('/api/users/:id/esqueceu-password', async (req, res) => {
  const userId = req.params.id;
  const { password } = req.body;

  try {
    if (!password || password.trim().length < 6) {
      return res.status(400).json({ message: 'A nova senha deve ter pelo menos 6 caracteres.' });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'Utilizador não encontrado.' });

    user.password = password; // 🔐 Será encriptado no pre('save')
    await user.save();

    res.status(200).json({ message: 'Senha atualizada com sucesso.' });
  } catch (err) {
    console.error('Erro ao alterar senha:', err);
    res.status(500).json({ message: 'Erro ao alterar senha.' });
  }
});




// Rota para login do usuário
app.post('/api/login', [
  body('username').notEmpty().withMessage('Nome de usuário é obrigatório'),
  body('password').notEmpty().withMessage('Senha é obrigatória'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { username, password } = req.body;

    // Encontrar o usuário pelo username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Usuário não encontrado!' });
    }

    // Comparar a senha
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Senha inválida!' });
    }

    // Gerar o token JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret', {
      expiresIn: '1h',
    });

    return res.status(200).json({ message: 'Login bem-sucedido!', token });
  } catch (error) {
    next(error); // Passa o erro para o middleware de tratamento de erros
  }
});

// Rota para obter os dados do perfil do usuário autenticado
app.get('/api/profile', authenticateToken, async (req, res, next) => {
  try {
    const userId = req.user?.userId;

    if (!userId) {
      return res.status(400).json({ message: 'ID do usuário não encontrado no token' });
    }

    console.log(`🔍 Buscando perfil do usuário ID: ${userId}`); // Usando o emoji corretamente

    // Buscar o usuário no banco de dados
    const user = await User.findById(userId).select('fullName username profilePicture');

    if (!user) {
      console.warn(`⚠️ Usuário com ID ${userId} não encontrado.`);
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    console.log(`✅ Perfil do usuário encontrado:`, user);
    return res.status(200).json(user);
  } catch (error) {
    console.error('❌ Erro ao buscar perfil:', error);
    next(error); // Passa o erro para o middleware de tratamento de erros
  }
});

// Rota para atualizar o perfil do usuário autenticado
app.put('/api/profile', authenticateToken, upload.single('profilePicture'), async (req, res, next) => {
  try {
    const userId = req.user?.userId;

    if (!userId) {
      return res.status(400).json({ message: 'ID do usuário não encontrado no token' });
    }

    // Dados para atualizar
    const { fullName, username } = req.body;
    console.log('Dados recebidos:', { fullName, username, profilePicture: req.file?.filename });  // Log para depuração

    if (!fullName || !username) {
      return res.status(400).json({ message: 'Nome completo e nome de usuário são obrigatórios' });
    }

    // Preparar o caminho da imagem
    let profilePicture = '';
    if (req.file) {
      profilePicture = `uploads/${req.file.filename}`;
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { fullName, username, profilePicture },
      { new: true }
    ).select('fullName username profilePicture');

    if (!updatedUser) {
      return res.status(404).json({ message: 'Utilizador não encontrado' });
    }

    console.log('Utilizador atualizado:', updatedUser);  // Verifica os dados atualizados
    return res.status(200).json(updatedUser);
  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    next(error);
  }
});

// Rota para criar um novo serviço
app.post('/api/servicos', authenticateToken, async (req, res) => {
  try {
    const {
      dataServico, horaServico, status, autorServico, clienteId,
      nomeCompletoCliente, contatoCliente, marcaAparelho, modeloAparelho,
      problemaRelatado, solucaoInicial, valorTotal, observacoes
    } = req.body;

    // Validação do ID do cliente
    if (!mongoose.Types.ObjectId.isValid(clienteId)) {
      return res.status(400).json({ message: 'ID do cliente inválido' });
    }

    // Verifica se cliente existe
    const clienteExiste = await Cliente.findById(clienteId);
    if (!clienteExiste) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    // Gera número único para o serviço
    const numeroServico = new Date().getTime().toString();

    const novoServico = new Servico({
      numero: numeroServico,
      dataServico,
      horaServico,
      status,
      cliente: clienteId, // Agora usando ObjectId
      responsavel: autorServico,
      observacoes,
      autorServico,
      nomeCompletoCliente,
      contatoCliente,
      modeloAparelho,
      marcaAparelho,
      problemaRelatado,
      solucaoInicial,
      valorTotal: Number(valorTotal) // Garante que é número
    });

    await novoServico.save();
    res.status(201).json({ message: 'Serviço criado com sucesso!', servico: novoServico });

  } catch (error) {
    console.error('Erro ao criar serviço:', error);
    res.status(500).json({ 
      message: 'Erro ao criar serviço',
      error: error.message // Mostra o erro completo
    });
  }
});

// Rota para listar todos os serviços
app.get('/api/servicos', authenticateToken, async (req, res, next) => {
  try {
    const servicos = await Servico.find();
    return res.status(200).json(servicos);
  } catch (error) {
    next(error);
  }
});


app.get('/api/servicos/:id', authenticateToken, async (req, res, next) => {
  try {
    const servicos = await Servico.findOne({ _id: req.params.id });
    return res.status(200).json(servicos);
  } catch (error) {
    next(error);
  }
});


app.put('/api/servicos/:id', authenticateToken, upload.array('imagens'), async (req, res) => {
  try {
    const {
      dataServico, horaServico, status, nomeCliente, telefoneContato,
      modeloAparelho, marcaAparelho, problemaRelatado,
      solucaoInicial, valorTotal, observacoes, autorServico,
    } = req.body;

    // Imagens novas via upload
    const imagensNovas = req.files ? req.files.map(file => file.filename) : [];

    // Imagens já existentes (enviadas como string JSON ou array)
    let imagensExistentes = [];
    if (req.body.imagensExistentes) {
      if (typeof req.body.imagensExistentes === 'string') {
        imagensExistentes = [req.body.imagensExistentes];
      } else if (Array.isArray(req.body.imagensExistentes)) {
        imagensExistentes = req.body.imagensExistentes;
      }
    }

    const imagensFinal = [...imagensExistentes, ...imagensNovas];

    const updateData = {
      dataServico,
      horaServico,
      status,
      nomeCompletoCliente: nomeCliente,
      contatoCliente: telefoneContato,
      modeloAparelho,
      marcaAparelho,
      problemaRelatado,
      solucaoInicial,
      valorTotal: parseFloat(valorTotal) || 0,
      observacoes,
      autorServico,
      imagens: imagensFinal,
    };

    const servicoAtualizado = await Servico.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );

    if (!servicoAtualizado) {
      return res.status(404).json({ message: 'Serviço não encontrado!' });
    }

    res.status(200).json({ 
      message: 'Serviço atualizado com sucesso!', 
      servico: servicoAtualizado 
    });

  } catch (error) {
    console.error('Erro ao atualizar serviço:', error);
    res.status(500).json({
      message: 'Erro ao atualizar serviço',
      error: error.message,
    });
  }
});


// Rota PATCH para atualizar apenas o status do serviço
app.patch('/api/servicos/:id', authenticateToken, async (req, res, next) => {
  try {
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ message: 'O status é obrigatório.' });
    }

    const servicoAtualizado = await Servico.findByIdAndUpdate(
      req.params.id,
      { status: status },
      { new: true }
    );

    if (!servicoAtualizado) {
      return res.status(404).json({ message: 'Serviço não encontrado!' });
    }

    res.status(200).json({ message: 'Status atualizado com sucesso!', servico: servicoAtualizado });
  } catch (error) {
    console.error('Erro ao atualizar status do serviço:', error);
    next(error);
  }
});

app.get('/api/clientes/:id/orcamentos', authenticateToken, async (req, res) => {
  try {
    const clienteId = req.params.id;

    // Verificar se o cliente existe
    const cliente = await Cliente.findById(clienteId);
    if (!cliente) {
      return res.status(404).json({ message: 'Cliente não encontrado!' });
    }
    // Buscar serviços relacionados ao cliente usando string
    const orcamentos = await Servico.find({ cliente: clienteId });
    res.status(200).json(orcamentos);
  } catch (error) {
    res.status(500).json({ 
      message: 'Erro ao buscar orçamentos do cliente', 
      error: error.message 
    });
  }
});

// Rota para obter serviços de um cliente específico
app.get('/api/clientes/:id', authenticateToken, async (req, res) => {
  try {
    // Verifica se o ID é válido
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'ID inválido' });
    }

    const cliente = await Cliente.findById(req.params.id);
    
    if (!cliente) {
      return res.status(404).json({ message: 'Cliente não encontrado!' });
    }

    // Retorna o cliente formatado
    const clienteObj = cliente.toObject();
    clienteObj.id = clienteObj._id;
    delete clienteObj._id;

    res.status(200).json(clienteObj);
  } catch (error) {
    console.error('Erro ao buscar cliente:', error);
    res.status(500).json({ 
      message: 'Erro ao buscar cliente',
      error: error.message 
    });
  }
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Rota para "Esqueceu a senha"
app.post('/api/esqueceu-password', [
  body('email').isEmail().withMessage('E-mail inválido')
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;

  try {
    console.log('Processando solicitação de recuperação de senha para e-mail:', email);
    // Verificar credenciais de e-mail
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      throw new Error('Credenciais de e-mail não configuradas no servidor');
    }

    const user = await User.findOne({ email });

    if (!user) {
      console.log('Usuário não encontrado com o e-mail:', email); // Log de erro
      return res.status(404).json({ message: 'Usuário com este e-mail não foi encontrado.' });
    }

    // Gerar o token de reset
    const resetToken = crypto.randomBytes(32).toString('hex');
    console.log('Token de redefinição gerado:', resetToken); // Log de token gerado

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hora

    await user.save();

    const resetLink = `${process.env.api_url}/api/reset-password/${resetToken}`;
    console.log('Link de redefinição gerado:', resetLink); // Log do link de reset

    // Envio de e-mail
    await transporter.sendMail({
      to: user.email,
      subject: 'Redefinição de Senha - Tec Online',
      html: `
        <h3>Olá, ${user.fullName}</h3>
        <p>Você solicitou a redefinição de sua senha.</p>
        <p>Clique no link abaixo para criar uma nova senha:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>Se você não solicitou isso, ignore este e-mail.</p>
      `,
    });

    return res.status(200).json({
      message: 'Link de redefinição de senha enviado por e-mail com sucesso.',
    });
  } catch (error) {
    console.error('Erro ao tentar redefinir senha:', error); // Log de erro detalhado
    res.status(500).json({
      message: 'Ocorreu um erro interno ao processar a solicitação.',
      error: error.message,
    });
  }
});

// Rota para redefinir a senha (versão corrigida)
app.post('/api/reset-password', async (req, res) => {
  const { token, novaSenha } = req.body;

  try {
    // Validação básica
    if (!token || !novaSenha) {
      return res.status(400).json({ 
        success: false,
        message: 'Token e nova senha são obrigatórios' 
      });
    }

    // Encontrar usuário pelo token válido
    const user = await User.findOne({ 
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Token inválido ou expirado' 
      });
    }

    // Atualizar senha
    user.password = novaSenha; 
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    return res.status(200).json({ 
      success: true,
      message: 'Senha redefinida com sucesso!' 
    });

  } catch (error) {
    console.error('Erro no reset de senha:', error);
    res.status(500).json({ 
      success: false,
      message: 'Erro ao redefinir senha',
      error: error.message 
    });
  }
});

// Rota para verificar token (corrigida)
app.get('/api/verify-token/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const user = await User.findOne({ 
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ 
        valid: false,
        message: 'Token inválido ou expirado' 
      });
    }

    res.status(200).json({ 
      valid: true,
      message: 'Token válido',
      email: user.email // Opcional: retornar email associado
    });
  } catch (err) {
    res.status(500).json({ 
      valid: false,
      message: 'Erro ao verificar token',
      error: err.message 
    });
  }
});

// Rota para criação de cliente
app.post('/api/clientes', authenticateToken, async (req, res) => {
  try {
    const {
      nome,
      morada,
      codigoPostal,
      contacto,
      email,
      contribuinte,
      codigoCliente,
      numeroCliente
    } = req.body;

    // Validação simples
    if (!nome || !contacto) {
      return res.status(400).json({ message: 'Nome e contacto são obrigatórios' });
    }

    // Verificar se já existe cliente com o mesmo email ou número de cliente
    const existingCliente = await Cliente.findOne({
      $or: [
        { email: email },
        { numeroCliente: numeroCliente }
      ]
    });

    if (existingCliente) {
      return res.status(400).json({ message: 'Já existe um cliente com este e-mail ou número de cliente' });
    }

    const novoCliente = new Cliente({
      nome,
      morada,
      codigoPostal,
      contacto,
      email,
      contribuinte,
      codigoCliente,
      numeroCliente
    });

    await novoCliente.save();

    return res.status(201).json({ message: 'Cliente criado com sucesso!', cliente: novoCliente });
  } catch (error) {
    console.error('Erro ao criar cliente:', error);
    res.status(500).json({ message: 'Erro interno ao criar cliente', error: error.message });
  }
});

app.get('/api/clientes', authenticateToken, async (req, res) => {
  try {
    const clientes = await Cliente.find();
    
    // Mapear para converter _id em id
    const clientesFormatados = clientes.map(c => {
      const obj = c.toObject();  // transforma documento mongoose em objeto JS simples
      obj.id = obj._id;
      delete obj._id;
      return obj;
    });
    res.json(clientesFormatados);
  } catch (err) {
    res.status(500).json({ message: 'Erro ao buscar clientes', error: err.message });
  }
});


// Rota para editar cliente existente
app.put('/api/clientes/:id', authenticateToken, async (req, res) => {
  try {
    const { nome, morada, codigoPostal, contacto, email, contribuinte, codigoCliente, numeroCliente } = req.body;
    const { id } = req.params;

    // Validação dos campos obrigatórios
    if (!nome || !morada || !codigoPostal || !contacto || !email || !contribuinte) {
      return res.status(400).json({ message: 'Todos os campos são obrigatórios!' });
    }

    // Verifica se o cliente existe
    const clienteExistente = await Cliente.findById(id);
    if (!clienteExistente) {
      return res.status(404).json({ message: 'Cliente não encontrado!' });
    }

    // Atualiza os campos
    clienteExistente.nome = nome;
    clienteExistente.morada = morada;
    clienteExistente.codigoPostal = codigoPostal;
    clienteExistente.contacto = contacto;
    clienteExistente.email = email;
    clienteExistente.contribuinte = contribuinte;
    clienteExistente.codigoCliente = codigoCliente;
    clienteExistente.numeroCliente = numeroCliente;

    // Salva a atualização
    await clienteExistente.save();

    res.json({ message: 'Cliente atualizado com sucesso!', cliente: clienteExistente });

  } catch (error) {
    res.status(500).json({ message: 'Erro ao atualizar cliente', error: error.message });
  }
});


// Rota para deletar um cliente e reorganizar os códigos
app.delete('/api/clientes/:id', authenticateToken, async (req, res) => {
  try {
    const clienteId = req.params.id;

    const clienteDeletado = await Cliente.findByIdAndDelete(clienteId);

    if (!clienteDeletado) {
      return res.status(404).json({ message: 'Cliente não encontrado!' });
    }

    // Buscar todos os clientes restantes, ordenados por codigoCliente
    const clientesRestantes = await Cliente.find().sort({ codigoCliente: 1 });

    // Atualizar os códigos sequencialmente (01, 02, 03, ...)
    for (let i = 0; i < clientesRestantes.length; i++) {
      const novoCodigo = (i + 1).toString().padStart(2, '0');
      if (clientesRestantes[i].codigoCliente !== novoCodigo) {
        clientesRestantes[i].codigoCliente = novoCodigo;
        await clientesRestantes[i].save();
      }
    }

    res.status(200).json({ message: 'Cliente deletado com sucesso e códigos reorganizados!' });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao deletar cliente', error: error.message });
  }
});

// Rota para criar um novo cliente com codigoCliente automático
app.post('/api/clientes', authenticateToken, async (req, res) => {
  try {
    const {
      nome,
      morada,
      codigoPostal,
      contacto,
      email,
      contribuinte
    } = req.body;

    // Verificação dos campos obrigatórios
    if (!nome || !morada || !codigoPostal || !contacto || !email || !contribuinte) {
      return res.status(400).json({ message: 'Todos os campos são obrigatórios!' });
    }

    // Buscar todos os clientes ordenados por codigoCliente
    const clientesExistentes = await Cliente.find().sort({ codigoCliente: 1 });

    // Definir o próximo código disponível
    const novoCodigo = (clientesExistentes.length + 1).toString().padStart(2, '0');

    const novoCliente = new Cliente({
      nome,
      morada,
      codigoPostal,
      contacto,
      email,
      contribuinte,
      codigoCliente: novoCodigo,
      numeroCliente: novoCodigo // Se usas esse campo
    });

    await novoCliente.save();

    res.status(201).json({
      message: 'Cliente criado com sucesso!',
      cliente: novoCliente
    });
  } catch (error) {
    res.status(500).json({
      message: 'Erro ao criar cliente',
      error: error.message
    });
  }
});

// Rota para buscar clientes por nome ou e-mail
app.get('/api/clientes/busca', authenticateToken, async (req, res) => {
  try {
    const { nome, email } = req.query;
    let filtro = {};

    if (nome) {
      filtro.nome = new RegExp(nome, 'i'); // Filtra pelo nome, ignorando maiúsculas/minúsculas
    }

    if (email) {
      filtro.email = new RegExp(email, 'i'); // Filtra pelo e-mail, ignorando maiúsculas/minúsculas
    }

    const clientes = await Cliente.find(filtro);

    if (clientes.length === 0) {
      return res.status(404).json({ message: 'Nenhum cliente encontrado com esses critérios.' });
    }

    res.status(200).json(clientes);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar clientes', error: error.message });
  }
});

app.get('/', (req, res) => {
    res.status(200).json('Welcome, your app is working well!2 🚀');
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`✅ Servidor rodando na porta ${PORT}`);
});