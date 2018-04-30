from datetime import datetime, timedelta

from flask import jsonify
from flask import request
from flask.views import MethodView

from sample.api import api
from .. import swagger

@swagger.validator("hm")
def hour_minute_validator(value, tag, schema):
    if isinstance(value, str):
        try:
            datetime.strptime(value, '%H:%M')
        except ValueError:
            return "Incorrect hour-minute format, should be hh:mm"
    return None

@swagger.translator("hm")
def hour_minute_translator(value):
    try:
        inst = datetime.strptime(value, '%H:%M')
        delta = timedelta(hours=inst.hour, minutes=inst.minute)
        return delta.seconds
    except ValueError as e:
        raise e

@api.route('/helloworld')
@swagger.doc('doc.json#/helloworld')
def helloworld():
    return jsonify(code=0, message='ok')

@api.route('/query')
@swagger.doc('doc.json#/query')
def query():
    return jsonify(code=0, message='ok',data={
        "query1": request.query_dict["query1"],
        "query2": request.query_dict["query2"],
    })

@api.route('/path/<id1>/<int:id2>')
@swagger.doc('doc.json#/path')
def path(id1,id2):
    return jsonify(code=0, message='ok',data={
        "id1": id1,
        "id2": id2,
    })

@api.route('/form', methods=["POST"])
@swagger.doc('doc.json#/form')
def form():
    return jsonify(code=0, message='ok',data={
        "f1": request.form_dict["f1"],
        "f2": request.form_dict["f2"],
        "f3": request.form_dict["f3"],
        "f4": request.form_dict["f4"],
    })

@api.route('/json', methods=["PUT"])
@swagger.doc('doc.json#/json')
def json():
    return jsonify(code=0, message='ok',data=request.json)

@api.route('/params/<int:id>', methods=["PATCH"])
@swagger.doc('doc.json#/params')
def params(id):
    return jsonify(code=0, message='ok',data={
        "json": request.json,
        "id": id,
        "query1": request.query_dict.get("query1",None),
        "query2": request.query_dict["query2"],
    })

@api.route('/optional_params/<int:id>', methods=["POST"])
@api.route('/optional_params', defaults={'id': None}, methods=['POST'])
@swagger.doc('doc.json#/optional_params')
def optional_params(id):
    return jsonify(code=0, message='ok',data={
        "json": request.json,
        "id": id,
    })

########################################################################################################################

@api.route('/validate_disable', methods=["POST"])
@swagger.doc('doc.json#/validate_disable',validate_flag=False)
def validate_disable():
    return jsonify(code=0, message='ok')

@api.route('/error_tip')
@swagger.doc('doc.json#/error_tip')
def error_tip():
    return jsonify(code=0, message='ok')

@api.route('/yaml_sample')
@swagger.doc('doc.yml#/yaml_sample')
def yaml_sample():
    return jsonify(code=0, message='ok')

# Method View
class UserAPI(MethodView):
    decorators = [
        swagger.doc('doc.yml#/method_view')
    ]
    def get(self):
        return jsonify(code=0, message='ok')

api.add_url_rule('/method_view',view_func=UserAPI.as_view('user_method_view'))

@api.route('/endpoints', defaults={'id': None}, endpoint="endpoints", methods=["GET","POST"])
@api.route('/endpoint/<int:id>', endpoint="endpoint", methods=["PUT","DELETE"])
@swagger.doc('doc.yml#/endpoints_get', endpoint="endpoints", blueprint=api, methods=["GET"])
@swagger.doc('doc.yml#/endpoints_post', endpoint="endpoints", blueprint=api, methods=["POST"])
@swagger.doc('doc.yml#/endpoint_all', endpoint="endpoint", blueprint=api)
def endpoint_method(id):
    return jsonify(code=0, message='ok')

@api.route('/standalone', methods=["PUT","DELETE", "POST"])
@swagger.doc('standalone.yml', methods=["PUT", "POST"])
@swagger.doc('standalone.json', methods=["DELETE"])
def standalone():
    return jsonify(code=0, message='ok')
########################################################################################################################

@api.route('/composition', methods=["POST"])
@swagger.doc('doc.json#/composition')
def composition():
    return jsonify(code=0, message='ok')

@api.route('/inheritance', methods=["POST"])
@swagger.doc('doc.json#/inheritance')
def inheritance():
    return jsonify(code=0, message='ok')

@api.route('/group', methods=["POST"])
@swagger.doc('doc.json#/group')
def group():
    return jsonify(code=0, message='ok')

@api.route('/item_group', methods=["POST"])
@swagger.doc('doc.json#/item_group')
def item_group():
    return jsonify(code=0, message='ok')

########################################################################################################################

@api.route('/custome_validator', methods=["POST"])
@swagger.doc('validator.yml#/custome_validator')
def custome_validator():
    return jsonify(code=0, message='ok', data=request.form_dict["time"])

@api.route('/base_validator', methods=["POST"])
@swagger.doc('validator.yml#/base_validator')
def base_validator():
    return jsonify(code=0, message='ok')

@api.route('/array_validator', methods=["POST"])
@swagger.doc('validator.yml#/array_validator')
def array_validator():
    return jsonify(code=0, message='ok')

@api.route('/dep_validator', methods=["POST"])
@swagger.doc('validator.yml#/dep_validator')
def dep_validator():
    return jsonify(code=0, message='ok')
