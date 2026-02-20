"""
WSGI entry point для Gunicorn и других серверов
"""
import os
import sys

# Добавляем папку app в sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app import app, socketio

if __name__ == "__main__":
    # Для разработки используйте:
    # socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    # Для продакшена используйте gunicorn с eventlet:
    # gunicorn --worker-class eventlet -w 1 wsgi:app
    socketio.run(app, host='0.0.0.0', port=os.environ.get('APP_PORT', 5000), debug=False)

