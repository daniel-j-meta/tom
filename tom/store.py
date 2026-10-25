"""Small durable store. Secret values are authenticated ciphertext, never JSON config."""

import base64
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Store:
    def __init__(self, directory: Path, key: bytes):
        if len(key) != 32:
            raise ValueError("Vault key must contain 32 bytes")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(directory / "tom.sqlite")
        os.chmod(directory / "tom.sqlite", 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS instances (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL,
              subnet INTEGER UNIQUE NOT NULL, state TEXT NOT NULL DEFAULT 'stopped',
              control_owner TEXT, control_until REAL, touched REAL NOT NULL,
              created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS secrets (
              instance TEXT NOT NULL, name TEXT NOT NULL, value BLOB NOT NULL,
              PRIMARY KEY (instance,name));
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY, instance TEXT NOT NULL REFERENCES instances(id),
              message TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
              result TEXT, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (
              id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
              instance TEXT, created REAL NOT NULL);
        """)
        self.cipher = AESGCM(key)

    def close(self):
        self.db.close()

    def all_instances(self):
        return [dict(x) for x in self.db.execute("SELECT * FROM instances ORDER BY created")]

    def instance(self, instance_id):
        row = self.db.execute("SELECT * FROM instances WHERE id=?", (instance_id,)).fetchone()
        return dict(row) if row else None

    def create_instance(self, owner, name):
        used = {x["subnet"] for x in self.all_instances()}
        subnet = next(x for x in range(1, 251) if x not in used)
        iid = uuid.uuid4().hex
        now = time.time()
        with self.db:
            self.db.execute(
                "INSERT INTO instances(id,owner,name,subnet,touched,created) VALUES(?,?,?,?,?,?)",
                (iid, owner, name, subnet, now, now),
            )
        return self.instance(iid)

    def update(self, iid, **fields):
        allowed = {"state", "control_owner", "control_until", "touched"}
        if not fields or not set(fields) <= allowed:
            raise ValueError("Invalid instance fields")
        with self.db:
            self.db.execute(
                "UPDATE instances SET " + ",".join(f"{x}=?" for x in fields) + " WHERE id=?",
                (*fields.values(), iid),
            )

    def set_secret(self, iid, name, value):
        nonce = os.urandom(12)
        ciphertext = nonce + self.cipher.encrypt(
            nonce, json.dumps(value).encode(), f"{iid}:{name}".encode()
        )
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO secrets VALUES(?,?,?)", (iid, name, ciphertext))

    def get_secret(self, iid, name):
        row = self.db.execute(
            "SELECT value FROM secrets WHERE instance=? AND name=?", (iid, name)
        ).fetchone()
        if not row:
            return None
        value = row[0]
        return json.loads(self.cipher.decrypt(value[:12], value[12:], f"{iid}:{name}".encode()))

    def secret_names(self, iid):
        return [r[0] for r in self.db.execute("SELECT name FROM secrets WHERE instance=?", (iid,))]

    def proxy_credentials(self, iid):
        token = self.get_secret(iid, "internal/proxy-token")
        if token is None:
            token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
            self.set_secret(iid, "internal/proxy-token", token)
        return token

    def enqueue(self, iid, message, job_id):
        old = self.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if old:
            if old["instance"] != iid or old["message"] != message:
                raise ValueError("Submission ID was already used for different content")
            return dict(old)
        with self.db:
            self.db.execute(
                "INSERT INTO jobs(id,instance,message,created) VALUES(?,?,?,?)",
                (job_id, iid, message, time.time()),
            )
        return self.job(job_id)

    def job(self, job_id):
        r = self.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(r) if r else None

    def jobs(self, iid):
        return [
            dict(r)
            for r in self.db.execute(
                "SELECT * FROM jobs WHERE instance=? ORDER BY created DESC LIMIT 50", (iid,)
            )
        ]

    def queued(self):
        return [
            dict(r)
            for r in self.db.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY created")
        ]

    def finish_job(self, job_id, state, result=None):
        with self.db:
            self.db.execute("UPDATE jobs SET state=?,result=? WHERE id=?", (state, result, job_id))

    def recover_jobs(self):
        with self.db:
            self.db.execute(
                "UPDATE jobs SET state='interrupted',result=? WHERE state='running'",
                ("Server restarted. Check the conversation before retrying.",),
            )

    def audit(self, actor, action, iid=None):
        with self.db:
            self.db.execute(
                "INSERT INTO audit(actor,action,instance,created) VALUES(?,?,?,?)",
                (actor, action, iid, time.time()),
            )
