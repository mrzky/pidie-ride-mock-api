const express = require('express');
const serverless = require('serverless-http');

const app = express();

// Root mock endpoint
app.get('/', (req, res) => {
  res.json({ message: 'hello' });
});

// Example extra endpoint
app.get('/users', (req, res) => {
  res.json([
    { id: 1, name: 'Alice' },
    { id: 2, name: 'Bob' }
  ]);
});

module.exports = serverless(app);
