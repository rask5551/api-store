import base64
import os
import threading

def generate_secret_key():
    return base64.b64encode(os.urandom(32)).decode()

def schedule_secret_key_regeneration(app):
    def regenerate_secret_key():
        with app.app_context():
            app.config['SECRET_KEY'] = generate_secret_key()

    def schedule_next_execution():
        threading.Timer(300.0, regenerate_secret_key).start()

    schedule_next_execution()