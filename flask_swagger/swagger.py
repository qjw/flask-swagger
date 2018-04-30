import json
import logging
import os
from functools import wraps

from flask import Blueprint
from flask import request
from flask import url_for
from jsonschema import FormatChecker
from werkzeug.utils import redirect

from . import const
from .utils import _parse_docstring, _load_docstring, SwaggerEndpointInfo, \
    _set_swagger_info, _load_validate_schema, _get_swagger_info, _translate_string_data, _translator_do
from .validator import *

logger = logging.getLogger(__name__)

class Swagger:
    DATETIME = 'datetime'
    DATE = 'date'
    VIN = 'vin'
    PLATE = 'plate'
    MOBILE = 'mobile'

    def __init__(self, *args, **kwargs):
        self.app = None
        # app的配置
        self.config = None
        self.info = None

        # 加载/解析spec的锁
        import threading
        self.load_lock = threading.Lock()
        # 已经解析过的spec
        self.schema = None

        self.doc_root = None
        # 具体的开关
        # 是否开启文档访问
        self.doc_enable = False
        # 是否开启校验（全局）
        self.validate_enable = True
        # 是否开启跨域（默认开启）
        self.enable_cors = True

        # 已经加载过的文档
        self.doc_cache = {}

        self.custome_validators = {}
        self.custome_translators = {}

        from jsonschema.validators import extend
        from jsonschema import Draft4Validator
        self.validator_handle = extend(Draft4Validator, {
            'validator': self._internalValidatorDispatch
        }, 'FlasggerSchema')

    def _init_validator(self, validators):
        if not validators:
            validators = [
                Swagger.DATETIME,
                Swagger.DATE,
                Swagger.VIN,
                Swagger.PLATE,
                Swagger.MOBILE
            ]
        _validator_dict = {
            Swagger.DATETIME: [datetime_validator, datetime_translator],
            Swagger.DATE: [date_validator, date_translator],
            Swagger.VIN: [re_validator_maker("^[A-HJ-NPR-Z\\d]{8}[\\dX][A-HJ-NPR-Z\\d]{8}$"), None],
            Swagger.PLATE: [re_validator_maker("^[\u4e00-\u9fa5]{1}[A-Z]{1}[A-Z0-9]{4,5}[A-Z0-9\u4e00-\u9fa5]$"), None],
            Swagger.MOBILE: [re_validator_maker("^1[3|4|5|8][0-9]{9}$"), None],
        }
        for name in validators:
            v =  _validator_dict.get(name, None)
            if not v:
                raise Exception("internal validator/translator (%s) not found"%(name))
            self.register_validator(name, v[0])
            if v[1]:
                self.register_translator(name, v[1])


    # 内置传入的validator
    def _internalValidatorDispatch(self, validator, value, instance, schema):
        func = self.custome_validators.get(value, None)
        if not func:
            raise Exception("validator(%s) not found, value(%s) schema(%s)"%(value, instance, schema))

        errors = func(validator, value, instance, schema)
        for error in errors:
            yield error

    def _load_doc_root(self):
        doc_root = self.app.root_path
        self.doc_root = self.config.get('doc_root', None)
        # 已经设置了变量
        if self.doc_root is not None:
            # 如果是相对路径，那么加上根目录
            if not self.doc_root.startswith('/'):
                doc_root = os.path.join(doc_root, self.doc_root)
            else:
                doc_root = self.doc_root
        self.doc_root = os.path.abspath(doc_root) + "/"
        logger.info("set doc root %s(%s)",doc_root, self.doc_root)

    # 读取配置
    def _load_config(self):
        self.config = self.app.config.get('SWAGGER', {})
        self.info = self.config.get('info', const.INFORMATION)

        self._load_doc_root()
        self.doc_enable = self.config.get('doc_enable',False)
        self.validate_enable = self.config.get('validate_enable',True)

        logger.info("set doc_enable(%r) validate_enable(%r)", self.doc_enable, self.validate_enable)
        if not self.doc_enable and not self.validate_enable:
            raise Exception("doc_enable/validate_enable enable at least one")

    # 枚举Url
    def _load_spec(self):
        # 已经初始化过，就不用再初始化了
        if self.schema:
            return self.schema

        self.load_lock.acquire()
        try:
            if self.schema:
                return self.schema
            self.schema = self._load_spec_imp()
        finally:
            self.load_lock.release()
        return self.schema

    def _load_spec_imp(self):
        base_url = self.config.get('base_url',None)
        logger.info("base url %s", base_url)

        securityDefinitions = {}
        custom_headers = self.config.get('custom_headers',None)
        if custom_headers and isinstance(custom_headers, list):
            for item in custom_headers:
                securityDefinitions[item] = {
                    "type": "apiKey",
                    "in": "header",
                    "name": item
                }

        from collections import defaultdict
        data = {
            "swagger": self.config.get('swagger_version', "2.0"),
            "basePath": self.config.get('base_url',"/"),
            "info": self.info,
            "securityDefinitions": securityDefinitions,
            "paths": defaultdict(dict),
            "definitions": defaultdict(dict)
        }

        # https://swagger.io/docs/specification/api-host-and-base-path/
        if self.config.get('host'):
            data['host'] = self.config.get('host')
        if self.config.get('schemes'):
            data['schemes'] = [self.config.get('schemes')]
        # https://swagger.io/docs/specification/authentication/
        # if self.config.get("securityDefinitions"):
        #     data["securityDefinitions"] = self.config.get(
        #         'securityDefinitions'
        #     )
        # set defaults from template
        # if self.template is not None:
        #     data.update(self.template)

        paths = data['paths']
        definitions = data['definitions']
        ignore_verbs = set(("HEAD", "OPTIONS"))

        # technically only responses is non-optional
        optional_fields = [
            'tags', 'consumes', 'produces', 'schemes', 'security',
            'deprecated', 'operationId', 'externalDocs'
        ]

        for rule in self.get_url_mappings(None):
            endpoint = self.app.view_functions[rule.endpoint]
            methods = dict()
            for verb in rule.methods.difference(ignore_verbs):
                if Swagger._is_valid_dispatch_view(endpoint):
                    endpoint.methods = endpoint.methods or ['GET']
                    if verb in endpoint.methods:
                        methods[verb.lower()] = endpoint
                elif hasattr(endpoint, 'methods') and verb in endpoint.methods:
                    verb = verb.lower()
                    methods[verb] = getattr(endpoint.view_class, verb)
                else:
                    methods[verb.lower()] = endpoint
            operations = dict()
            for verb, method in methods.items():
                if verb is None or method is None:
                    continue

                summary, description, swag = _parse_docstring(
                    self.doc_cache,
                    method,
                    endpoint=rule.endpoint,
                    method=verb,
                    root=self.doc_root
                )

                if swag is not None:

                    params = swag.get('parameters', [])

                    responses = swag.get('responses', {})
                    responses = {
                        str(key): value
                        for key, value in responses.items()
                    }

                    operation = dict(
                        summary=summary,
                        description=description,
                        responses=responses
                    )
                    # parameters - swagger ui dislikes empty parameter lists
                    if len(params) > 0:
                        operation['parameters'] = params
                    # other optionals
                    for key in optional_fields:
                        if key in swag:
                            operation[key] = swag.get(key)
                    operations[verb] = operation

            if len(operations):
                rule = str(rule)
                if base_url is not None and rule.startswith(base_url):
                    rule = rule[len(base_url):]
                # old regex '(<(.*?\:)?(.*?)>)'
                for arg in re.findall('(<([^<>]*:)?([^<>]*)>)', rule):
                    rule = rule.replace(arg[0], '{%s}' % arg[2])
                paths[rule].update(operations)
        return json.dumps(data,ensure_ascii=False,sort_keys=True)

    def get_url_mappings(self, rule_filter=None):
        rule_filter = rule_filter or (lambda rule: True)
        app_rules = [
            rule for rule in self.app.url_map.iter_rules()
            if rule_filter(rule)
            ]
        return app_rules

    def _is_valid_dispatch_view(endpoint):
        klass = endpoint.__dict__.get('view_class', None)
        return klass and hasattr(klass, 'dispatch_request') \
               and hasattr(endpoint, 'methods')

    def _init_view(self):
        swagger_endpoint = const.SWAGGER_END_POINT

        blueprint = Blueprint(swagger_endpoint,__name__)
        # 如果swagger ui和后端的spec不在一个域，需要开启
        if self.config.get("enable_cors", True):
            from flask_cors import CORS
            CORS(blueprint)

        @blueprint.route("/")
        def api_index():
            url = url_for(swagger_endpoint + '.api_spec')
            url = "%s%s"%(self.config.get("domain",const.DOMAIN), url)
            swagger_ui = self.config.get("swagger_ui", const.SWAGGER_UI_URL)
            return redirect('%s/index.html?url=%s'%(swagger_ui, url))

        @blueprint.route("/" + const.SPEC_URL)
        def api_spec():
            return self._load_spec()

        self.app.register_blueprint(blueprint, url_prefix=self.config.get('url_prefix',const.URL_PREFIX))

        @self.app.before_first_request
        def check():
            self._check_validator()

    def init_app(self, app, validators=None):
        if self.app:
            raise Exception("init swagger by app yet")
        self.app = app
        self._load_config()
        if self.doc_enable:
            self._init_view()
        self._init_validator(validators)

    def _validator_callback(self, function):
        def handle(validator, value, instance, schema):
            # 注意，顺序调换了
            r = function(instance, value, schema)
            if not r:
                return
            else:
                from jsonschema import ValidationError
                yield ValidationError(r)

        return handle

    def register_validator(self, tag, function):
        if not self.app:
            raise Exception("must init swagger by app first")
        if not isinstance(tag, str):
            raise Exception("invalid validator tag %s" % (tag))

        if self.custome_validators.get(tag):
            logger.warn("validator tag (%s) exist", tag)
        self.custome_validators[tag] = self._validator_callback(function)

    def validator(self, tag):
        def decorator(function):
            self.register_validator(tag, function)
            @wraps(function)
            def wrapper(*args, **kwargs):
                return function(*args, **kwargs)
            return wrapper
        return decorator

    def register_translator(self, tag, function):
        if not self.app:
            raise Exception("must init swagger by app first")
        if not isinstance(tag, str):
            raise Exception("invalid translator tag %s" % (tag))

        if self.custome_translators.get(tag):
            logger.warn("translator tag (%s) exist", tag)
        self.custome_translators[tag] = function

    def translator(self, tag):
        def decorator(function):
            self.register_translator(tag, function)
            @wraps(function)
            def wrapper(*args, **kwargs):
                return function(*args, **kwargs)
            return wrapper
        return decorator

    def doc(self, filepath, endpoint=None, methods=None, blueprint=None, validate_flag=None):
        if not self.app:
            raise Exception("must init swagger by app first")
        def decorator(function):
            final_filepath = filepath

            # 子路径，例如@swag.doc('api.json#/entry')
            if filepath.rfind('#') >= 0:
                swag_subpath = filepath.split('#')[-1]
            else:
                swag_subpath = None

            if swag_subpath is not None:
                if not swag_subpath.startswith('/'):
                    raise AttributeError("invalid json sub path")
                # 去掉前面的‘/’
                swag_subpath = swag_subpath[1:]
                # 不支持多级
                if swag_subpath.find('/') >= 0:
                    raise AttributeError("invalid json sub path,only one depth")
                length = - (len(swag_subpath) + 2)
                final_filepath = final_filepath[0:length]

            # 文件类型（json/yaml）
            swag_type = final_filepath.split('.')[-1]
            if swag_type not in ('yml', 'json'):
                raise AttributeError("Currently only yml or json supported")

            swag_path = final_filepath

            swag_obj = SwaggerEndpointInfo(swag_path,swag_subpath,swag_type)
            _set_swagger_info(function, endpoint, blueprint, methods, swag_obj)

            local_validate = self.validate_enable if validate_flag is None else validate_flag
            if local_validate:
                swag = _load_docstring(
                    self.doc_cache,
                    swag_obj,
                    self.doc_root)
                _load_validate_schema(function, swag, swag_obj)

            @wraps(function)
            def wrapper(*args, **kwargs):
                swag_info = _get_swagger_info(function, request.endpoint, request.method)
                if not swag_info:
                    raise Exception("function %s have NO swag_info"%(function.__str__()))

                if swag_info.swag_param_body is not None:
                    request.json_dict = request.json
                    self.validator_handle(
                        swag_info.swag_param_body,
                        format_checker=FormatChecker()
                    ).validate(request.json_dict)

                    # http://stackoverflow.com/questions/17404348/simple-python-validation-library-which-reports-all-validation-errors-instead-of
                    # validator = customValidator(schema)
                    # errors = [e for e in validator.iter_errors(input_dict)]
                    # if len(errors):
                    #     return errors

                request.query_dict = {}
                if swag_info.swag_param_query is not None:
                    data, translator_tags = _translate_string_data(swag_info.swag_param_query, request.args)
                    if data is None:
                        raise Exception("translate_string_data fail (%s|%s)"%(filepath,function.__str__()))
                    request.query_dict = data
                    self.validator_handle(
                        swag_info.swag_param_query,
                        format_checker=FormatChecker()
                    ).validate(data)
                    _translator_do(data, translator_tags, self.custome_translators)

                if swag_info.swag_param_path is not None:
                    data, translator_tags = _translate_string_data(swag_info.swag_param_path, request.view_args)
                    self.validator_handle(
                        swag_info.swag_param_path,
                        format_checker=FormatChecker()
                    ).validate(data)
                    _translator_do(data, translator_tags, self.custome_translators)

                request.form_dict = {}
                if swag_info.swag_param_formdata is not None:
                    data, translator_tags = _translate_string_data(swag_info.swag_param_formdata, request.form)
                    if data is None:
                        raise Exception("translate_string_data fail (%s|%s)"%(filepath,function.__str__()))
                    request.form_dict = data
                    self.validator_handle(
                        swag_info.swag_param_formdata,
                        format_checker=FormatChecker()
                    ).validate(data)
                    _translator_do(data, translator_tags, self.custome_translators)

                return function(*args, **kwargs)
            return wrapper
        return decorator

    def _enum_endpoint(self, func):
        ignore_verbs = set(("HEAD", "OPTIONS"))
        for rule in self.get_url_mappings(None):
            endpoint = self.app.view_functions[rule.endpoint]
            methods = dict()
            for verb in rule.methods.difference(ignore_verbs):
                if Swagger._is_valid_dispatch_view(endpoint):
                    endpoint.methods = endpoint.methods or ['GET']
                    if verb in endpoint.methods:
                        methods[verb.lower()] = endpoint
                elif hasattr(endpoint, 'methods') and verb in endpoint.methods:
                    verb = verb.lower()
                    methods[verb] = getattr(endpoint.view_class, verb)
                else:
                    methods[verb.lower()] = endpoint
            for verb, method in methods.items():
                if verb is None or method is None:
                    continue

                summary, description, swag = _parse_docstring(
                    self.doc_cache,
                    method,
                    endpoint=rule.endpoint,
                    method=verb,
                    root=self.doc_root
                )
                if not swag:
                    continue

                func(summary, description, swag, verb, method, rule.endpoint)

    def _check_validator(self):
        def f(summary, description, swag, verb, method, endpoint):
            swag = swag.get('parameters', None)
            if not swag or type(swag) != list:
                return

            for item in swag:
                if type(item) != dict:
                    continue
                item_type = item.get('in', None)
                if item_type == "body":  # 不支持json的validator
                    continue

                # 检查validator/translator是否存在
                validator = item.get('validator', None)
                if validator:
                    logger.debug("check validator %s %s %s %s", validator, verb, method, endpoint)
                    if not self.custome_validators.get(validator):
                        raise Exception("validator(%s) not FOUND (%s)" % (validator, endpoint))
                translator = item.get('translator', None)
                if translator:
                    logger.debug("check translator %s %s %s %s", translator, verb, method, endpoint)
                    if not self.custome_translators.get(translator):
                        raise Exception("translator(%s) not FOUND (%s)" % (translator, endpoint))
        self._enum_endpoint(f)