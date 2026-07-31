"""Dev entrypoint: `python run.py` runs the web app on port 5070.
For the scheduled sync in dev, run `python sync.py` in a second terminal.

Debug (the Werkzeug debugger executes arbitrary code) is opt-in via
FLASK_DEBUG=1, and a debug server never binds beyond localhost.
"""
from app import app

if __name__ == '__main__':
    import os
    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')
    app.run(host='127.0.0.1' if debug else '0.0.0.0',
            port=int(os.environ.get('PORT', 5070)), debug=debug)
