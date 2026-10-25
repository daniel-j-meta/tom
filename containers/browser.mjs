import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import {createRequire} from 'node:module';
const require = createRequire('/app/package.json');
const {chromium} = require('playwright-core');
const config = JSON.parse(fs.readFileSync('/run/tom/broker.json', 'utf8'));
const context = await chromium.launchPersistentContext('/home/node/profile', {
  channel: 'chromium', headless: true, chromiumSandbox: true,
  viewport: {width: 1280, height: 800},
  proxy: {server: config.proxy, username: config.instance, password: config.token},
  args: ['--remote-debugging-port=9222', '--proxy-bypass-list=<-loopback>',
         '--disable-background-networking', '--disable-sync'],
});
// Chrome keeps CDP on loopback. Forward only inside the instance's isolated Docker network.
const server = http.createServer((req, res) => {
  const upstream = http.request({host: '127.0.0.1', port: 9222, path: req.url,
    method: req.method, headers: {...req.headers, host: '127.0.0.1:9222'}}, r => {
    let body = '';
    r.on('data', chunk => body += chunk);
    r.on('end', () => {
      body = body.replaceAll('127.0.0.1:9222', req.headers.host);
      res.writeHead(r.statusCode, {'Content-Type': r.headers['content-type'] || 'application/json'});
      res.end(body);
    });
  });
  upstream.on('error', () => {res.writeHead(502); res.end();});
  req.pipe(upstream);
});
server.on('upgrade', (req, socket, head) => {
  const upstream = net.connect(9222, '127.0.0.1', () => {
    const headers = Object.entries(req.headers)
      .filter(([k]) => k !== 'host' && k !== 'origin')
      .map(([k,v]) => `${k}: ${v}`).join('\r\n');
    upstream.write(`${req.method} ${req.url} HTTP/1.1\r\nHost: 127.0.0.1:9222\r\n${headers}\r\n\r\n`);
    if (head.length) upstream.write(head);
    socket.pipe(upstream); upstream.pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
  socket.on('close', () => upstream.destroy());
});
server.listen(9223, '0.0.0.0', () => console.log('Tom browser ready; Chromium sandbox enabled'));
const stop = async () => {server.close(); await context.close(); process.exit(0);};
process.on('SIGTERM', stop); process.on('SIGINT', stop);
