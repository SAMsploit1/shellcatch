// LAB ONLY: deliberately vulnerable to OS command injection via child_process.exec.
// Try: /node/ping?host=127.0.0.1;id
const http = require('http');
const { exec } = require('child_process');

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/ping') {
    res.writeHead(404).end('not found\n');
    return;
  }
  const host = url.searchParams.get('host') || '127.0.0.1';
  exec(`ping -c 1 -W 1 ${host}`, { timeout: 10000 }, (err, stdout, stderr) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' }).end(stdout + stderr);
  });
}).listen(3000, '127.0.0.1');
