
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const lockfile = require('proper-lockfile');

function encrypt(text, password) {
  const key = crypto.createHash('sha256').update(password).digest();
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(encrypted, password) {
  const key = crypto.createHash('sha256').update(password).digest();
  const iv = Buffer.alloc(16, 0);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function DBManager(folderPath, userFile = 'users.json.enc', userSecret, logFile = 'logs.json.enc', logSecret) {
  if (!fs.existsSync(folderPath)) fs.mkdirSync(folderPath, { recursive: true });

  // ==== LOG SYSTEM ====
  function logsPath() {
    return path.join(folderPath, logFile);
  }
  function loadLogs() {
    if (!fs.existsSync(logsPath())) return [];
    const encrypted = fs.readFileSync(logsPath(), 'utf8');
    if (!encrypted) return [];
    try {
      return JSON.parse(decrypt(encrypted, logSecret));
    } catch {
      return [];
    }
  }
  async function saveLogs(logs) {
    await lockfile.lock(logsPath(), { realpath: false });
    try {
      const encrypted = encrypt(JSON.stringify(logs, null, 2), logSecret);
      fs.writeFileSync(logsPath(), encrypted);
    } finally {
      await lockfile.unlock(logsPath(), { realpath: false });
    }
  }
  async function log({ username, operation, target, status, details }) {
    let logs = [];
    if (fs.existsSync(logsPath())) logs = loadLogs();
    logs.push({
      timestamp: new Date().toISOString(),
      username,
      operation,
      target,
      status,
      details,
    });
    await saveLogs(logs);
  }

  // ==== USER SYSTEM ====
  function usersPath() {
    return path.join(folderPath, userFile);
  }
  function loadUsers() {
    if (!fs.existsSync(usersPath())) return [];
    const encrypted = fs.readFileSync(usersPath(), 'utf8');
    if (!encrypted) return [];
    try {
      return JSON.parse(decrypt(encrypted, userSecret));
    } catch {
      return [];
    }
  }
  async function saveUsers(users) {
    await lockfile.lock(usersPath());
    try {
      const encrypted = encrypt(JSON.stringify(users, null, 2), userSecret);
      fs.writeFileSync(usersPath(), encrypted);
    } finally {
      await lockfile.unlock(usersPath());
    }
  }
  function dbFile(username, dbName) {
    return path.join(folderPath, `${username}_${dbName}.json.enc`);
  }
  async function saveDBFile(file, data, password) {
    await lockfile.lock(file, { realpath: false });
    try {
      const encrypted = encrypt(JSON.stringify(data, null, 2), password);
      fs.writeFileSync(file, encrypted);
    } finally {
      await lockfile.unlock(file, { realpath: false });
    }
  }

  // ==== API ====
  return {
    // Criar usuário
    async createUser({ username, password, dbpassword }) {
      try {
        await lockfile.lock(usersPath());
        const users = loadUsers();
        if (users.some(u => u.username === username)) {
          await log({ username, operation: 'createUser', target: 'user', status: 'fail', details: 'Usuário já existe' });
          throw new Error('Usuário já existe');
        }
        users.push({ username, password, dbpassword, dbs: [] });
        await saveUsers(users);
        await log({ username, operation: 'createUser', target: 'user', status: 'success' });
      } finally {
        await lockfile.unlock(usersPath());
      }
    },

    // Autenticar usuário
    async authenticate(username, password) {
      const users = loadUsers();
      const user = users.find(u => u.username === username && u.password === password);
      await log({
        username,
        operation: 'authenticate',
        target: 'user',
        status: user ? 'success' : 'fail',
        details: user ? undefined : 'Credenciais inválidas'
      });
      return user ? { ...user } : null;
    },

    // Criar novo DB
    async createDB(username, dbName, data = {}) {
      const file = dbFile(username, dbName);
      await lockfile.lock(file, { realpath: false });
      try {
        const users = loadUsers();
        const user = users.find(u => u.username === username);
        if (!user) {
          await log({ username, operation: 'createDB', target: dbName, status: 'fail', details: 'Usuário não existe' });
          throw new Error('Usuário não existe');
        }
        if (user.dbs.includes(dbName)) {
          await log({ username, operation: 'createDB', target: dbName, status: 'fail', details: 'DB já existe' });
          throw new Error('DB já existe');
        }
        await saveDBFile(file, data, user.dbpassword);
        user.dbs.push(dbName);
        await saveUsers(users);
        await log({ username, operation: 'createDB', target: dbName, status: 'success' });
      } finally {
        await lockfile.unlock(file, { realpath: false });
      }
    },

    // Listar DBs do usuário
    listDBs(username) {
      const users = loadUsers();
      const user = users.find(u => u.username === username);
      return user ? user.dbs : [];
    },

    // Ler dados de um DB
    async readDB(username, dbName) {
      const users = loadUsers();
      const user = users.find(u => u.username === username);
      if (!user || !user.dbs.includes(dbName)) {
        await log({ username, operation: 'readDB', target: dbName, status: 'fail', details: 'Sem permissão ou DB não existe' });
        throw new Error('Sem permissão ou DB não existe');
      }
      const encrypted = fs.readFileSync(dbFile(username, dbName), 'utf8');
      await log({ username, operation: 'readDB', target: dbName, status: 'success' });
      return JSON.parse(decrypt(encrypted, user.dbpassword));
    },

    // Salvar dados em DB
    async saveDB(username, dbName, data) {
      const users = loadUsers();
      const user = users.find(u => u.username === username);
      if (!user || !user.dbs.includes(dbName)) {
        await log({ username, operation: 'saveDB', target: dbName, status: 'fail', details: 'Sem permissão ou DB não existe' });
        throw new Error('Sem permissão ou DB não existe');
      }
      const file = dbFile(username, dbName);
      await saveDBFile(file, data, user.dbpassword);
      await log({ username, operation: 'saveDB', target: dbName, status: 'success' });
    },

    // Deletar DB
    async deleteDB(username, dbName) {
      const file = dbFile(username, dbName);
      await lockfile.lock(file, { realpath: false });
      try {
        const users = loadUsers();
        const user = users.find(u => u.username === username);
        if (!user || !user.dbs.includes(dbName)) {
          await log({ username, operation: 'deleteDB', target: dbName, status: 'fail', details: 'Sem permissão ou DB não existe' });
          return;
        }
        if (fs.existsSync(file)) fs.unlinkSync(file);
        user.dbs = user.dbs.filter(db => db !== dbName);
        await saveUsers(users);
        await log({ username, operation: 'deleteDB', target: dbName, status: 'success' });
      } finally {
        await lockfile.unlock(file, { realpath: false });
      }
    },

    // Buscar logs (ex: admin, auditoria)
    async getLogs({ username } = {}) {
      const logs = loadLogs();
      if (username) return logs.filter(log => log.username === username);
      return logs;
    }
  };
}

module.exports = DBManager;
