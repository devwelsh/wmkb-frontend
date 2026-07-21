"""KB sync engine — mirrors Warehouse Manager's Knowledge Base into the local
SQLite store and file cache.

Full re-sync each run: pull categories + documents, upsert by remote_id, prune
anything that disappeared, and (re)download files only when the content hash or
size changed or the local copy is missing. Network downloads happen outside the
DB write transaction so the public site's readers are never blocked for long.

Run as a one-shot via run_sync(), or as a long-lived daemon (`python sync.py`),
which is how the separate `wmkb-sync` compose service stays scheduled.
"""
import os
import re
import time
import traceback

import app as wmkb
import wm_client


def _conn():
    return wmkb.get_db()


def _doc_ext(doc):
    ext = (doc.get('ext') or '').lower()
    if not ext and doc.get('original_name'):
        ext = doc['original_name'].rsplit('.', 1)[-1].lower() if '.' in doc['original_name'] else ''
    return re.sub(r'[^a-z0-9]', '', ext)[:8] if ext else 'bin'


def _cache(name):
    return os.path.join(wmkb.CACHE_DIR, name)


def _safe_remove(name):
    if not name:
        return
    try:
        os.remove(_cache(name))
    except OSError:
        pass


def run_sync():
    """Perform one full sync. Returns a result dict (also written to sync_log)."""
    started = wmkb._now_iso()
    conn = _conn()
    base = ''
    try:
        c = wmkb.get_wm_connection(conn)
        base = (c.get('base_url') or '').strip().rstrip('/')
        key = (c.get('api_key') or '').strip()
    finally:
        conn.close()

    log_id = _log_start(started)
    if not base or not key:
        return _log_finish(log_id, started, 'error', 0, 0, 0,
                           'Warehouse Manager connection is not configured.')

    try:
        cats = wm_client.get_categories(base, key).get('categories', [])
        docs = wm_client.get_documents(base, key)
    except Exception as e:
        return _log_finish(log_id, started, 'error', 0, 0, 0, f'Fetch failed: {e}')

    # ── Categories: upsert + prune (fast, single transaction) ──
    conn = _conn()
    try:
        remote_cat_ids = set()
        for cat in cats:
            remote_cat_ids.add(cat['id'])
            conn.execute(
                "INSERT INTO kb_categories (remote_id, name, slug, sort_order, icon, doc_count) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(remote_id) DO UPDATE SET "
                "  name=excluded.name, slug=excluded.slug, sort_order=excluded.sort_order, "
                "  icon=excluded.icon, doc_count=excluded.doc_count",
                (cat['id'], cat.get('name', ''), cat.get('slug', ''),
                 cat.get('sort_order', 0), cat.get('icon', ''), cat.get('doc_count', 0)))
        if remote_cat_ids:
            ph = ','.join('?' * len(remote_cat_ids))
            conn.execute(f"DELETE FROM kb_categories WHERE remote_id NOT IN ({ph})",
                         tuple(remote_cat_ids))
        else:
            conn.execute("DELETE FROM kb_categories")
        conn.commit()
    except Exception as e:
        conn.close()
        return _log_finish(log_id, started, 'error', 0, 0, 0, f'Category upsert failed: {e}')

    # ── Documents: upsert metadata + prune (fast). Capture what files we need. ──
    import json
    try:
        remote_doc_ids = set()
        for d in docs:
            remote_doc_ids.add(d['id'])
            conn.execute(
                "INSERT INTO kb_documents "
                "(remote_id, category_remote_id, title, description, original_name, mime_type, "
                " file_size, file_sha256, vehicle_fitment, associated_parts, doc_type, ext, "
                " is_image, has_featured, created_at, sort_order) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(remote_id) DO UPDATE SET "
                "  category_remote_id=excluded.category_remote_id, title=excluded.title, "
                "  description=excluded.description, original_name=excluded.original_name, "
                "  mime_type=excluded.mime_type, file_size=excluded.file_size, "
                "  vehicle_fitment=excluded.vehicle_fitment, associated_parts=excluded.associated_parts, "
                "  doc_type=excluded.doc_type, ext=excluded.ext, is_image=excluded.is_image, "
                "  has_featured=excluded.has_featured, created_at=excluded.created_at, "
                "  sort_order=excluded.sort_order",
                (d['id'], d.get('category_id'), d.get('title', ''), d.get('description', ''),
                 d.get('original_name', ''), d.get('mime_type', ''), d.get('file_size', 0),
                 d.get('file_sha256', ''), d.get('vehicle_fitment', ''),
                 json.dumps(d.get('associated_parts', [])), d.get('doc_type', 'document'),
                 _doc_ext(d), 1 if d.get('is_image') else 0, 1 if d.get('has_featured') else 0,
                 d.get('created_at', ''), d.get('sort_order', 0)))
        # Prune documents that vanished upstream (and their cached files).
        existing = conn.execute("SELECT remote_id, local_file, local_featured FROM kb_documents").fetchall()
        for row in existing:
            if row['remote_id'] not in remote_doc_ids:
                _safe_remove(row['local_file'])
                _safe_remove(row['local_featured'])
                conn.execute("DELETE FROM kb_documents WHERE remote_id = ?", (row['remote_id'],))
        conn.commit()
    except Exception as e:
        conn.close()
        return _log_finish(log_id, started, 'error', len(cats), 0, 0, f'Document upsert failed: {e}')

    # Snapshot what each doc currently has locally, then release the connection
    # for the (slow) downloads so readers aren't blocked.
    local_state = {r['remote_id']: dict(r) for r in conn.execute(
        "SELECT remote_id, file_sha256, file_size, ext, local_file, local_featured FROM kb_documents"
    ).fetchall()}
    conn.close()

    remote_by_id = {d['id']: d for d in docs}
    files_downloaded = 0
    errors = []

    for rid, d in remote_by_id.items():
        try:
            st = local_state.get(rid, {})
            ext = _doc_ext(d)
            # ── Document file ──
            if d.get('has_file'):
                want = f"doc-{rid}.{ext}"
                have = st.get('local_file') or ''
                disk_ok = have and os.path.exists(_cache(have))
                changed = False
                rsha, rsize = d.get('file_sha256', ''), d.get('file_size', 0)
                if not disk_ok:
                    changed = True
                elif rsha and rsha != (st.get('file_sha256') or ''):
                    changed = True
                elif not rsha and rsize != (st.get('file_size') or 0):
                    changed = True
                elif have != want:
                    changed = True
                if changed:
                    ok = wm_client.download_document(base, key, rid, _cache(want))
                    if ok:
                        if have and have != want:
                            _safe_remove(have)
                        files_downloaded += 1
                        _update_local(rid, local_file=want, file_sha256=rsha, file_size=rsize)
                    else:
                        _update_local(rid, local_file='')
            else:
                if st.get('local_file'):
                    _safe_remove(st['local_file'])
                    _update_local(rid, local_file='')

            # ── Featured image ──
            if d.get('has_featured'):
                fwant = f"feat-{rid}.jpg"
                fhave = st.get('local_featured') or ''
                if not (fhave and os.path.exists(_cache(fhave))):
                    ok = wm_client.download_featured(base, key, rid, _cache(fwant))
                    if ok:
                        files_downloaded += 1
                        _update_local(rid, local_featured=fwant)
                    else:
                        _update_local(rid, local_featured='')
            else:
                if st.get('local_featured'):
                    _safe_remove(st['local_featured'])
                    _update_local(rid, local_featured='')
        except Exception as e:
            errors.append(f"doc {rid}: {e}")

    status = 'ok' if not errors else 'partial'
    return _log_finish(log_id, started, status, len(cats), len(docs), files_downloaded,
                       '; '.join(errors[:10]))


def _update_local(remote_id, **fields):
    if not fields:
        return
    sets = ', '.join(f"{k} = ?" for k in fields)
    conn = _conn()
    try:
        conn.execute(f"UPDATE kb_documents SET {sets} WHERE remote_id = ?",
                     (*fields.values(), remote_id))
        conn.commit()
    finally:
        conn.close()


def _log_start(started):
    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO sync_log (started_at, status) VALUES (?, 'running')", (started,))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _log_finish(log_id, started, status, cats, docs, files, error):
    finished = wmkb._now_iso()
    conn = _conn()
    try:
        conn.execute(
            "UPDATE sync_log SET finished_at=?, status=?, categories=?, documents=?, "
            "files_downloaded=?, error=? WHERE id=?",
            (finished, status, cats, docs, files, error or '', log_id))
        conn.commit()
    finally:
        conn.close()
    return {'status': status, 'started_at': started, 'finished_at': finished,
            'categories': cats, 'documents': docs, 'files_downloaded': files, 'error': error or ''}


def _daemon():
    print('[wmkb-sync] daemon started', flush=True)
    while True:
        conn = _conn()
        try:
            cfg = wmkb.get_sync_config(conn)
        finally:
            conn.close()
        interval = max(5, int(cfg.get('interval_minutes', 30)))
        if cfg.get('enabled', True):
            try:
                res = run_sync()
                print(f"[wmkb-sync] {res['status']}: {res['categories']} cats, "
                      f"{res['documents']} docs, {res['files_downloaded']} files"
                      + (f" — {res['error']}" if res['error'] else ''), flush=True)
            except Exception:
                traceback.print_exc()
            time.sleep(interval * 60)
        else:
            time.sleep(60)


if __name__ == '__main__':
    _daemon()
