from flask_pymongo import PyMongo
mongo = None
def init_app(app):
    global mongo
    app.config.setdefault('MONGO_URI', app.config.get('MONGO_URI', 'mongodb://localhost:27017/code_signing_portal'))
    mongo = PyMongo(app)
    return mongo
