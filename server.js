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

// Rota para registrar um novo usuário
app.post('/api/signup', [
  body('fullName').notEmpty().withMessage('Nome completo é obrigatório'),
  body('username').notEmpty().withMessage('Nome de usuário é obrigatório'),
  body('email').isEmail().withMessage('E-mail inválido'),
  body('password').isLength({ min: 6 }).withMessage('A senha deve ter pelo menos 6 caracteres'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { fullName, username, email, password } = req.body;

    // Verificar se o usuário ou o email já estão registrados
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Usuário ou e-mail já cadastrados' });
    }

    // Criar um novo usuário e salvar no banco de dados
    const newUser = new User({ fullName, username, email, password });
    await newUser.save();

    return res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    next(error); // Passa o erro para o middleware de tratamento de erros
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
app.post('/api/servicos', authenticateToken, async (req, res, next) => {
  try {
    console.log('Dados recebidos:', req.body); // Log para verificar os dados recebidos

    const {
      dataServico, horaServico, status, autorServico, nomeCliente, telefoneContato,
      marcaAparelho, modeloAparelho, problemaCliente, solucaoInicial, valorTotal, observacoes
    } = req.body;

    if (!dataServico || !horaServico || !status || !autorServico || !nomeCliente || !telefoneContato ||
        !marcaAparelho || !modeloAparelho || !problemaCliente || !solucaoInicial || valorTotal === null) {
      return res.status(400).json({ message: 'Todos os campos são obrigatórios!' });
    }

    const novoServico = new Servico({
      numero: new Date().getTime().toString(),
      data: dataServico,
      status: status,
      cliente: nomeCliente,
      descricao: problemaCliente,
      responsavel: autorServico,
      observacoes: observacoes,
      autorServico: autorServico,
      nomeCompletoCliente: nomeCliente,
      contatoCliente: telefoneContato,
      modeloAparelho: modeloAparelho,
      marcaAparelho: marcaAparelho,
      problemaRelatado: problemaCliente,
      solucaoInicial: solucaoInicial,
      valorTotal: valorTotal,
    });

    console.log('Serviço a ser salvo:', novoServico); // Log para verificar o serviço antes de salvar

    await novoServico.save();

    return res.status(201).json({ message: 'Serviço criado com sucesso!', servico: novoServico });
  } catch (error) {
    console.error('Erro ao criar serviço:', error); // Log detalhado do erro
    next(error);
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


app.put('/api/servicos/:id', authenticateToken, upload.array('imagens'), async (req, res, next) => {
  try {
    const {
      dataServico, horaServico, status, nomeCliente, telefoneContato,
      modeloAparelho, marcaAparelho, problemaCliente, solucaoInicial,
      valorTotal, observacoes, autorServico
    } = req.body;

    // pega nomes dos arquivos enviados
    const imagens = req.files.map(file => file.filename); // ou file.path se quiser o caminho completo

    const updateData = {
      dataServico,
      horaServico,
      status,
      nomeCliente,
      telefoneContato,
      modeloAparelho,
      marcaAparelho,
      problemaCliente,
      solucaoInicial,
      valorTotal: parseFloat(valorTotal),
      observacoes,
      autorServico,
      imagens,
    };

    const servicoAtualizado = await Servico.findByIdAndUpdate(req.params.id, updateData, { new: true });

    if (!servicoAtualizado) {
      return res.status(404).json({ message: 'Serviço não encontrado!' });
    }

    res.status(200).json({ message: 'Serviço atualizado com sucesso!', servico: servicoAtualizado });
  } catch (error) {
    console.error('Erro ao atualizar serviço:', error);
    next(error);
  }
});


const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

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
      console.log('Usuário não encontrado com o e-mail:', email);
      // Por segurança, retorne sempre 200 para não revelar quais e-mails estão cadastrados
      return res.status(200).json({ 
        success: true,
        message: 'Se o e-mail estiver cadastrado, você receberá um link de recuperação' 
      });
    }

    // Gerar o token de reset
    const resetToken = crypto.randomBytes(32).toString('hex');
    console.log('Token de redefinição gerado:', resetToken);

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hora
    await user.save();

    // Usar a URL do frontend para o link de reset
    const frontendUrl = process.env.FRONTEND_URL || `${req.protocol}://${req.get('host')}`;
    const resetLink = `${frontendUrl}/reset-password?token=${resetToken}`;
    console.log('Link de redefinição gerado:', resetLink);

    // Envio de e-mail
    try {
      await transporter.sendMail({
        to: user.email,
        subject: 'Redefinição de Senha - Tec Online',
        html: `
          <h3>Olá, ${user.fullName}</h3>
          <p>Você solicitou a redefinição de sua senha.</p>
          <p>Clique no link abaixo para criar uma nova senha:</p>
          <a href="${resetLink}">Redefinir Senha</a>
          <p>Se você não solicitou isso, ignore este e-mail.</p>
          <p>O link expirará em 1 hora.</p>
        `,
      });

      return res.status(200).json({
        success: true,
        message: 'Link de redefinição enviado para o e-mail cadastrado',
      });
    } catch (emailError) {
      console.error('Erro ao enviar e-mail:', emailError);
      // Reverter o token já que o e-mail falhou
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();
      
      return res.status(500).json({
        success: false,
        message: 'Erro ao enviar e-mail de recuperação',
      });
    }
  } catch (error) {
    console.error('Erro ao tentar redefinir senha:', error);
    next(error);
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
    const { nome, morada, codigoPostal, contacto, email, contribuinte, codigoCliente, numeroCliente } = req.body;

    if (!nome || !morada || !codigoPostal || !contacto || !email || !contribuinte) {
      return res.status(400).json({ message: 'Todos os campos são obrigatórios!' });
    }

    const novoCliente = new Cliente({
      nome, morada, codigoPostal, contacto, email, contribuinte, codigoCliente, numeroCliente
    });

    await novoCliente.save();
    res.status(201).json({ message: 'Cliente criado com sucesso!', cliente: novoCliente });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao criar cliente', error: error.message });
  }
});



app.get('/api/clientes', authenticateToken, async (req, res) => {
  try {
    const clientes = await Cliente.find();
    res.json(clientes);
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


// Rota para deletar um cliente
app.delete('/api/clientes/:id', authenticateToken, async (req, res) => {
  try {
    const clienteId = req.params.id;

    const clienteDeletado = await Cliente.findByIdAndDelete(clienteId);

    if (!clienteDeletado) {
      return res.status(404).json({ message: 'Cliente não encontrado!' });
    }

    res.status(200).json({ message: 'Cliente deletado com sucesso!' });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao deletar cliente', error: error.message });
  }
});


// Rota para buscar um cliente específico
app.get('/api/clientes/:id', authenticateToken, async (req, res) => {
  try {
    const clienteId = req.params.id;

    const cliente = await Cliente.findById(clienteId);

    if (!cliente) {
      return res.status(404).json({ message: 'Cliente não encontrado!' });
    }

    res.status(200).json(cliente);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar cliente', error: error.message });
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
    res.status(200).json('Welcome, your app is working well! 🚀');
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`✅ Servidor rodando na porta ${PORT}`);
});
