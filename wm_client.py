"""Outbound client for the Warehouse Manager external KB API.

All requests authenticate with an API key in the X-API-Key header (never the
URL). File downloads stream to a temp file and are atomically renamed into
place so a crashed/truncated download never leaves a "valid-looking" cache
file behind. Every call has a timeout and a size cap.
"""
import os
import tempfile

import requests

TIMEOUT = 20            # seconds per request
MAX_FILE_BYTES = 64 * 1024 * 1024   # hard cap on a single downloaded file


class WMClientError(Exception):
    pass


def _headers(api_key):
    return {'X-API-Key': api_key, 'Accept': 'application/json'}


def _url(base_url, path):
    return base_url.rstrip('/') + path


def test_connection(base_url, api_key):
    """Return (ok, message). Used by the admin 'Test' button."""
    if not base_url:
        return False, 'Base URL is not set'
    if not api_key:
        return False, 'API key is not set'
    try:
        r = requests.get(_url(base_url, '/api/external/kb/categories'),
                         headers=_headers(api_key), timeout=TIMEOUT)
    except requests.RequestException as e:
        return False, f'Could not reach Warehouse Manager: {e}'
    if r.status_code == 401:
        return False, 'API key rejected (401). Check the key.'
    if r.status_code == 403:
        return False, 'Knowledge Base module is disabled on Warehouse Manager (403).'
    if r.status_code != 200:
        return False, f'Unexpected response: HTTP {r.status_code}'
    try:
        data = r.json()
    except ValueError:
        return False, 'Response was not valid JSON (is the base URL correct?)'
    n = len(data.get('categories', []))
    return True, f'Connected — {n} categor{"y" if n == 1 else "ies"} visible.'


def get_categories(base_url, api_key):
    r = requests.get(_url(base_url, '/api/external/kb/categories'),
                     headers=_headers(api_key), timeout=TIMEOUT)
    if r.status_code != 200:
        raise WMClientError(f'categories: HTTP {r.status_code}')
    return r.json()


def get_documents(base_url, api_key):
    r = requests.get(_url(base_url, '/api/external/kb/documents'),
                     headers=_headers(api_key), timeout=TIMEOUT)
    if r.status_code != 200:
        raise WMClientError(f'documents: HTTP {r.status_code}')
    return r.json().get('documents', [])


def get_glossary(base_url, api_key):
    """Return the glossary terms list, or None when the Warehouse Manager
    version predates the glossary endpoint (404) — callers leave the local
    mirror untouched in that case."""
    r = requests.get(_url(base_url, '/api/external/kb/glossary'),
                     headers=_headers(api_key), timeout=TIMEOUT)
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise WMClientError(f'glossary: HTTP {r.status_code}')
    return r.json().get('terms', [])


def _download(base_url, api_key, path, dest_path):
    """Stream a file to dest_path atomically. Returns True on success,
    False if the source 404s (file gone), raises on other errors."""
    with requests.get(_url(base_url, path), headers={'X-API-Key': api_key},
                      stream=True, timeout=TIMEOUT) as r:
        if r.status_code == 404:
            return False
        if r.status_code != 200:
            raise WMClientError(f'{path}: HTTP {r.status_code}')
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dest_path), suffix='.part')
        size = 0
        try:
            with os.fdopen(fd, 'wb') as out:
                for chunk in r.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_FILE_BYTES:
                        raise WMClientError(f'{path}: exceeds {MAX_FILE_BYTES} byte cap')
                    out.write(chunk)
            os.replace(tmp, dest_path)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
    return True


def download_document(base_url, api_key, remote_id, dest_path):
    return _download(base_url, api_key, f'/api/external/kb/documents/{remote_id}/download', dest_path)


def download_featured(base_url, api_key, remote_id, dest_path):
    return _download(base_url, api_key, f'/api/external/kb/documents/{remote_id}/featured', dest_path)
