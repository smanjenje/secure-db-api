
const express = require('express');
const cors = require('cors');
const DBManager = require('./dbmanager');

const app = express();
const PORT = 5000;

// Configuração dos segredos (guarde seguro em produção!)
const dbm = DBManager(
  './dbs',
  'users.json.enc',
  'senhaDosUsuarios',
  'logs.json.enc',
  'senhaDosLogs'
);

app.use(cors());
app.use(express.json());

// Criar usuário
app.post('/api/user', async (req, res) => {
  try {
    const { username, password, dbpassword } = req.body;
    await dbm.createUser({ username, password, dbpassword });
    res.json({ message: 'Usuário criado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Autenticar usuário
app.post('/api/auth', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await dbm.authenticate(username, password);
    if (!user) return res.status(401).json({ error: 'Credenciais inválidas' });
    res.json({ message: 'Autenticado', user: { username: user.username } });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Criar DB
app.post('/api/db', async (req, res) => {
  try {
    const { username, dbName, data } = req.body;
    await dbm.createDB(username, dbName, data);
    res.json({ message: 'DB criado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Listar DBs do usuário
app.get('/api/dbs/:username', (req, res) => {
  try {
    const { username } = req.params;
    const dbs = dbm.listDBs(username);
    res.json({ dbs });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Ler dados de um DB
app.get('/api/db/:username/:dbName', async (req, res) => {
  try {
    const { username, dbName } = req.params;
    const data = await dbm.readDB(username, dbName);
    res.json({ data });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Salvar dados em DB
app.put('/api/db/:username/:dbName', async (req, res) => {
  try {
    const { username, dbName } = req.params;
    const { data } = req.body;
    await dbm.saveDB(username, dbName, data);
    res.json({ message: 'Dados salvos' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Deletar DB
app.delete('/api/db/:username/:dbName', async (req, res) => {
  try {
    const { username, dbName } = req.params;
    await dbm.deleteDB(username, dbName);
    res.json({ message: 'DB deletado' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Listar logs (admin/auditoria)
app.get('/api/logs', async (req, res) => {
  try {
    const { username } = req.query;
    const logs = await dbm.getLogs({ username });
    res.json({ logs });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`API rodando em http://localhost:${PORT}`);
});
