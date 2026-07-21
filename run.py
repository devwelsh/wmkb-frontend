"""Dev entrypoint: `python run.py` runs the web app on port 5070.
For the scheduled sync in dev, run `python sync.py` in a second terminal.
"""
from app import app

if __name__ == '__main__':
    import os
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5070)), debug=True)
