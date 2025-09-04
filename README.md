# Criado por Severino Victorino 

# Secure DB API

Banco de dados JSON criptografado multiusuário, concorrência inter-processos, sistema de logs, exposto via API Express + CORS.

## Instalação

```bash
git clone https://github.com/smanjenje/secure-db-api.git
cd secure-db-api
npm install
```

## Uso

```bash
npm start
```

API rodando em http://localhost:5000

## Endpoints

- `POST /api/user`  
  `{ username, password, dbpassword }`  
  Cria novo usuário.

- `POST /api/auth`  
  `{ username, password }`  
  Autentica usuário.

- `POST /api/db`  
  `{ username, dbName, data }`  
  Cria novo banco para usuário.

- `GET /api/dbs/:username`  
  Lista bancos do usuário.

- `GET /api/db/:username/:dbName`  
  Lê dados de um banco.

- `PUT /api/db/:username/:dbName`  
  `{ data }`  
  Salva dados em um banco.

- `DELETE /api/db/:username/:dbName`  
  Deleta banco.

- `GET /api/logs?username=...`  
  Lista logs (filtra por usuário se desejar).

## Segurança

- Arquivos de usuários, bancos e logs são criptografados.
- Controle de concorrência por locks de arquivos (inter-processos).
- Logs para auditoria e rastreabilidade.

## Observações

- Troque os segredos em `server.js` para ambiente seguro em produção!
- Para frontend, use qualquer framework (React, Vue, etc) e conecte via HTTP.
