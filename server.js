const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator'); // Para validação de dados
const multer = require('multer'); // Para uploads (não usado aqui, mas configurado)
const path = require('path');
const fs = require('fs'); // Para criar pasta uploads, se não existir
dotenv.config();

const User = require('./models/User');
const Servico = require('./models/Servicos'); 
const Cliente = require('./models/Cliente'); 

const app = express();

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 3000;

// Criar pasta uploads se não existir
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());  // Também para interpretar JSON no corpo da requisição

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

// Configuração do multer para armazenamento de imagem (não obrigatório aqui)
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

    // Hash da password antes de guardar
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ fullName, username, email, password: hashedPassword, telefone, role });
    await newUser.save();

    return res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    next(error);
  }
});

// Rota para buscar todos os usuários
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find();
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
    const updateData = { ...req.body };

    // Se password vazia, elimina para não atualizar
    if (!updateData.password || updateData.password.trim() === '') {
      delete updateData.password;
    } else {
      // Se password foi enviada, faz hash
      updateData.password = await bcrypt.hash(updateData.password, 10);
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updateData, {
      new: true,
      runValidators: true,
    });

    if (!updatedUser) {
      return res.status(404).json({ message: 'Utilizador não encontrado' });
    }

    res.status(200).json({ message: 'Utilizador atualizado com sucesso!', user: updatedUser });
  } catch (error) {
    console.error('Erro ao atualizar utilizador:', error);
    res.status(500).json({ message: 'Erro ao atualizar utilizador' });
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
    console.log('Dados recebidos:', req.body);

    const {
      dataServico, horaServico, status, autorServico, clienteId, // Adicione clienteId aqui
      nomeCompletoCliente, contatoCliente, marcaAparelho, modeloAparelho, 
      problemaRelatado, solucaoInicial, valorTotal, observacoes
    } = req.body;

    // Validação adicional para clienteId
    if (!clienteId) {
      return res.status(400).json({ message: 'ID do cliente é obrigatório!' });
    }

    // Verificar se o cliente existe
    const cliente = await Cliente.findById(clienteId);
    if (!cliente) {
      return res.status(404).json({ message: 'Cliente não encontrado!' });
    }

    const novoServico = new Servico({
      numero: new Date().getTime().toString(),
      dataServico,
      horaServico,
      status,
      cliente,
      clienteId, // Armazene o ID do cliente
      responsavel: autorServico,
      observacoes,
      autorServico,
      nomeCompletoCliente,
      contatoCliente,
      modeloAparelho,
      marcaAparelho,
      problemaRelatado,
      solucaoInicial,
      valorTotal,
    });

    await novoServico.save();
    return res.status(201).json({ message: 'Serviço criado com sucesso!', servico: novoServico });
  } catch (error) {
    console.error('Erro ao criar serviço:', error);
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

    const imagens = req.files.map(file => file.filename);

    const updateData = {
      dataServico: dataServico,
      horaServico: horaServico,
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
      valorTotal: parseFloat(valorTotal),
      imagens
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

    // Buscar orçamentos relacionados a este cliente
    // (Assumindo que seu modelo Servico tem um campo clienteId)
    const orcamentos = await Servico.find({ clienteId: clienteId });
    
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
    const clienteId = req.params.id;
    console.log('ID recebido:', clienteId);

    // validar id antes de buscar
    if (!mongoose.Types.ObjectId.isValid(clienteId)) {
      return res.status(400).json({ message: 'ID do cliente inválido' });
    }

    const cliente = await Cliente.findById(clienteId);
    if (!cliente) {
      return res.status(404).json({ message: 'Cliente não encontrado!' });
    }
    res.status(200).json(cliente);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar cliente', error: error.message });
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

    const clienteObj = cliente.toObject();
    clienteObj.id = clienteObj._id;
    delete clienteObj._id;

    res.status(200).json(clienteObj);
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
    res.status(200).json('Welcome, your app is working well!2 🚀');
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`✅ Servidor rodando na porta ${PORT}`);
});