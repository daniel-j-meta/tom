#!/usr/local/bin/node
// OpenClaw's documented exec SecretRef protocol; only the model key is resolvable.
import fs from 'node:fs';
let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
  if (input.length > 8192) process.exit(1);
}
try {
  const request = JSON.parse(input);
  if (request.protocolVersion !== 1 || !Array.isArray(request.ids) ||
      request.ids.some(id => id !== 'providers/openai/apiKey')) throw new Error('Invalid request');
  const {url, token, instance} = JSON.parse(fs.readFileSync('/run/tom/broker.json', 'utf8'));
  const result = await fetch(url, {
    method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${token}`},
    body: JSON.stringify({instance}), signal: AbortSignal.timeout(5000),
  });
  if (!result.ok) throw new Error('Unavailable');
  const {value} = await result.json();
  console.log(JSON.stringify({protocolVersion: 1, values: {'providers/openai/apiKey': value}}));
} catch {
  // Resolver errors must never contain credential values or response bodies.
  console.log(JSON.stringify({protocolVersion: 1, values: {}, errors: {
    'providers/openai/apiKey': {code: 'NOT_FOUND'},
  }}));
  process.exitCode = 1;
}
