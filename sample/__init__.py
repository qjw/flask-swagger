from flask_swagger.swagger import Swagger
import logging

import jsonschema
from flask import Flask, jsonify
from flask import make_response
from sample.config import Config

url_prefix="/api/v123456"
swagger = Swagger()

def init_view(app):
    @app.route('%s/app_view'%(url_prefix), endpoint="app_view")
    @swagger.doc('doc.json#/app_view', endpoint="app_view")
    def app_view():
        return jsonify(code=0, message='ok')

def init_router(app):
    from sample.api import api
    from flask_cors import CORS
    CORS(app)
    CORS(api)
    app.register_blueprint(api, url_prefix=url_prefix)

def create_app():
    app = Flask(__name__)
    app.config.update(Config or {})
    logging.basicConfig(level=logging.DEBUG)


    @app.errorhandler(jsonschema.ValidationError)
    def handle_bad_request(e):
        return make_response(jsonify(code=400,
                                     message=e.schema.get('error', '参数校验错误'),
                                     details=e.message,
                                     schema=str(e.schema)), 200)

    swagger.init_app(app)
    init_router(app)
    init_view(app)
    return app