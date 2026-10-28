"""Short-lived, server-side contact challenges shared by application workers."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import fcntl


class ContactVerificationStore:
    lifetime = 300
    cooldown = 60
    max_attempts = 5

    def __init__(self, path, secret):
        self.path = Path(path)
        self.secret = secret.encode()

    @contextmanager
    def _records(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(self.path) + '.lock', os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(descriptor, 'a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                try:
                    with self.path.open() as stream:
                        records = json.load(stream)
                except FileNotFoundError:
                    records = {}
                now = time.time()
                records = {key: value for key, value in records.items()
                           if value['expires_at'] > now}
                yield records
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(mode='w', dir=self.path.parent,
                                                     prefix='.email-verification-', delete=False) as stream:
                        temporary = stream.name
                        json.dump(records, stream)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, self.path)
                finally:
                    if temporary and os.path.exists(temporary):
                        os.unlink(temporary)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _digest(self, token, code):
        return hmac.new(self.secret, f'{token}:{code}'.encode(), hashlib.sha256).hexdigest()

    def start(self, previous, subject, issuer, submit_url):
        with self._records() as records:
            old = records.get(previous)
            if old and time.time() - old['sent_at'] < self.cooldown:
                return None
            if previous:
                records.pop(previous, None)
            token = secrets.token_urlsafe(32)
            code = f'{secrets.randbelow(1000000):06d}'
            records[token] = dict(subject=subject, issuer=issuer, submit_url=submit_url,
                                  digest=self._digest(token, code), attempts=0,
                                  sent_at=time.time(), expires_at=time.time() + self.lifetime)
        return token, code

    def get(self, token):
        with self._records() as records:
            return records.get(token)

    def discard(self, token):
        with self._records() as records:
            records.pop(token, None)

    def verify(self, token, code):
        with self._records() as records:
            record = records.get(token)
            if not record:
                return 'expired', None
            record['attempts'] += 1
            if hmac.compare_digest(record['digest'], self._digest(token, code)):
                records.pop(token)
                return 'verified', record
            if record['attempts'] >= self.max_attempts:
                records.pop(token)
                return 'locked', None
            return 'invalid', record


# Backward-compatible name for integrations using the original email store.
EmailVerificationStore = ContactVerificationStore
