import copy
import json
import logging
import os

import jsonref
import sys
import yaml

logger = logging.getLogger(__name__)

class SwaggerEndpointInfo:
    def __init__(self, swag_path, swag_subpath, swag_type):
        self.swag_path = swag_path
        self.swag_subpath = swag_subpath
        self.swag_type = swag_type
        self.swag_param_body = None
        self.swag_param_query = None
        self.swag_param_path = None
        self.swag_param_formdata = None

def _load_from_file(swag_path, swag_type='yml', root=None):
    if swag_type not in ('yaml', 'yml', 'json'):
        raise AttributeError("Currently only yaml or yml or json supported (%s|%s)"%(swag_path, swag_type))

    old_swag_path = swag_path
    if root is None:
        swag_path = os.path.join(os.path.dirname(__file__), swag_path)
    else:
        swag_path = os.path.join(root, swag_path)

    try:
        logger.info("load from file (%s)", swag_path)
        return open(swag_path,encoding="utf8").read()
    except IOError:
        logger.info("load from file (%s) again with root", old_swag_path)
        return open(old_swag_path,encoding="utf8").read()


def _load_docstring(cache, swag_info,root):
    full_doc = None
    if swag_info.swag_path is None or swag_info.swag_type is None:
        return None

    if swag_info.swag_path is not None:
        full_doc = cache.get(swag_info.swag_path)
        if full_doc:
            # 已经cache过了
            if full_doc['parse']:
                # 已经parse过@ref
                if swag_info.swag_subpath:
                    swag = full_doc['swag'].get(swag_info.swag_subpath,None)
                else:
                    swag = full_doc['swag']
                if swag:
                    return copy.deepcopy(swag)
                else:
                    return None
            else:
                # 没有parse过，继续parse
                full_doc = full_doc['swag']
        else:
            # load from file
            full_doc = _load_from_file(swag_info.swag_path, swag_info.swag_type,root=root)
            cache[swag_info.swag_path] = {'parse': False,'swag': full_doc}
    else:
        return None

    if full_doc:
        try:
            if root is None:
                base_uri = 'file:' + os.path.dirname(sys.modules['__main__'].__file__) + '/'
            else:
                base_uri = 'file:' + root

            if swag_info.swag_type == 'yml':
                doc = yaml.load(full_doc)
            elif swag_info.swag_type == 'json':
                # 校验合法性，提供更为清晰的错误
                doc = json.loads(full_doc)
            else:
                return None

            from .yaml_loader import YamlLoader
            loader = YamlLoader()
            swag = jsonref.JsonRef.replace_refs(
                doc,
                base_uri=base_uri,
                loader=loader
            )
            cache[swag_info.swag_path] = {'parse': True, 'swag': swag}

            if swag_info.swag_subpath is not None:
                swag = swag.get(swag_info.swag_subpath,None)
                if swag:
                    return copy.deepcopy(swag)
            else:
                return copy.deepcopy(swag)

        except Exception as e:
            raise e
    return None

def _check_validate_endpoint(endpoint):
    if not isinstance(endpoint, str):
        raise AttributeError("endpoint MUST BE string")
    # if not endpoint.isalpha():
    #     raise AttributeError("endpoint (%s) MUST BE alpha" % endpoint)
    # todo 字母数字_

def _check_validate_method(method):
    if not isinstance(method, str):
        raise AttributeError("method MUST BE string")
    if not method.isalpha():
        raise AttributeError("method (%s) MUST BE alpha" % method)

def _adjust_endpoint(endpoint, blueprint):
    if not endpoint:
        return None
    if blueprint:
        return "%s.%s"%(blueprint.name, endpoint)
    else:
        return endpoint

def _set_swagger_info(function, endpoint, blueprint, methods, swag_obj):
    # ensure exist
    if not getattr(function, 'swag_paths', None):
        function.swag_paths = {}
    # 参数校验
    if endpoint:
        _check_validate_endpoint(endpoint)
    local_endpoint = _adjust_endpoint(endpoint, blueprint)
    if methods and not isinstance(methods, list):
        raise AttributeError("methods MUST BE list")

    if not local_endpoint and not methods:
        function.swag_path = swag_obj
    elif local_endpoint and not methods:
        function.swag_paths["%s/" % (local_endpoint)] = swag_obj
    elif local_endpoint and methods:
        for method in methods:
            _check_validate_method(method)
            function.swag_paths["%s/%s" % (local_endpoint, method.lower())] = swag_obj
    else:
        for method in methods:
            _check_validate_method(method)
            function.swag_paths["/%s" % (method.lower())] = swag_obj

def _get_swagger_info(function, endpoint, method):
    swag_path = getattr(function, 'swag_path', None)
    swag_paths = getattr(function, 'swag_paths', None)
    if not swag_paths:
        return swag_path

    method = method.lower()
    obj = swag_paths.get('%s/%s'%(endpoint,method),None)
    if obj:
        return obj
    obj = swag_paths.get('%s/' % (endpoint), None)
    if obj:
        return obj
    obj = swag_paths.get('/%s' % (method), None)
    if obj:
        return obj
    return None


def _parse_docstring(cache, obj, endpoint=None, method=None, root=None):
    swag_info = _get_swagger_info(obj, endpoint, method)
    if not swag_info:
        return '','',None
    swag = _load_docstring(
        cache,
        swag_info,
        root
    )
    if swag is None:
        return '','',None

    summary = swag.get('summary', '')
    description = swag.get('description','')
    swag.pop("summary", None)
    swag.pop("description", None)
    return summary,description,swag

def _load_validate_schema(function, schema, swag_info):
    swag = None
    if schema is not None:
        swag = schema.get('parameters', None)
    if swag is None or type(swag) != list:
        # 可以省略parameters
        return

    swag_param_query = {}
    swag_param_query_required = []
    swag_param_path = {}
    swag_param_path_required = []
    swag_param_formdata = {}
    swag_param_formdata_required = []
    # swag_param_body

    for item in swag:
        if type(item) != dict:
            continue
        item_name = item.get('name', None)
        item_type = item.get('in', None)
        if not item_name or not item_type or \
                not isinstance(item_name, str) or \
                not isinstance(item_type, str):
            raise Exception("invalid parameters name/type (%s)" % (function.__str__()))

        required = item.get('required', False)
        if not isinstance(required, bool):
            raise Exception("invalid parameters required flag (%s)" % (function.__str__()))

        # json 校验
        if item_type == 'body':
            swag_param_body = item.get('schema', None)

            # 不存在（默认）是false
            # 兼容body不为空的情况
            if not required and isinstance(swag_param_body["type"], str):
                swag_param_body["type"] = [swag_param_body["type"], "null"]
            """
            "parameters": [
                {
                    "in": "body",
                    "name":"body",
                    "description": "需要修改的内容",
                    "required": false,
                    "schema": {
                        "type": "string",
                        "default": "ok"
                    }
                }
            ]
            """

            if swag_param_body:
                swag_info.swag_param_body = swag_param_body
            elif required:
                raise Exception("body parameter required schema (%s)" % (function.__str__()))

        elif item_type == 'query':
            item.pop('in', None)
            item.pop('name', None)
            item.pop('required', None)
            swag_param_query[item_name] = item
            if required:
                swag_param_query_required.append(item_name)
        elif item_type == 'path':
            item.pop('in', None)
            item.pop('name', None)
            item.pop('required', None)
            swag_param_path[item_name] = item
            if required:
                swag_param_path_required.append(item_name)
        elif item_type == 'formData':
            item.pop('in', None)
            item.pop('name', None)
            item.pop('required', None)
            swag_param_formdata[item_name] = item
            if required:
                swag_param_formdata_required.append(item_name)
        else:
            raise Exception("invalid in type '%s' in function '%s'" % (item_type, function.__str__()))

    # 模拟成body的格式
    if swag_param_query and len(swag_param_query) > 0:
        swag_info.swag_param_query = {
            'properties': swag_param_query,
            'type': 'object'
        }
        if len(swag_param_query_required) > 0:
            swag_info.swag_param_query['required'] = swag_param_query_required

    if swag_param_path and len(swag_param_path) > 0:
        swag_info.swag_param_path = {
            'properties': swag_param_path,
            'type': 'object'
        }
        if len(swag_param_path_required) > 0:
            swag_info.swag_param_path['required'] = swag_param_path_required

    if swag_param_formdata and len(swag_param_formdata) > 0:
        swag_info.swag_param_formdata = {
            'properties': swag_param_formdata,
            'type': 'object'
        }
        if len(swag_param_formdata_required) > 0:
            swag_info.swag_param_formdata['required'] = swag_param_formdata_required

def _translator_do(data, translator_tags, translators):
    for name, tag in translator_tags.items():
        translator = translators.get(tag, None)
        if not translator:
            continue
        data[name] = translator(data[name])
    return data

def _translate_string_data(schema, data):
    translators = {}

    from werkzeug.datastructures import ImmutableMultiDict
    if isinstance(data, ImmutableMultiDict):
        rdict = data.to_dict(flat=True)
    elif isinstance(data, dict):
        rdict = data
    else:
        raise Exception("invalid schema type '%s'" % (json.dumps(schema, indent=2)))

    properties = schema.get('properties', None)
    if not isinstance(properties, dict):
        raise Exception("invalid schema properties '%s'" % (json.dumps(schema, indent=2)))
    for name, property in properties.items():
        if not isinstance(property, object):
            raise Exception("invalid schema properties.items '%s'" % (json.dumps(schema, indent=2)))
        type = property.get('type', None)
        if type is None:
            raise Exception("invalid schema type (null) '%s'" % (json.dumps(schema, indent=2)))

        # 存储翻译器
        validator = property.get("validator", None)
        if validator:
            translators[name] = validator
        else:
            translator = property.get("translator", None)
            if translator:
                translators[name] = translator

        # 排除空值
        value = rdict.get(name, None)
        if value is None or value == '':
            rdict.pop(name, None)
            continue

        if type == 'integer':
            value = rdict.get(name, None)
            if value is None or isinstance(value, int):
                continue

            # 尝试转成int，若失败，则肯定校验不过，直接return
            try:
                value_int = int(value)
                rdict[name] = value_int
            except TypeError as te:
                return rdict, translators
            except ValueError as ve:
                return rdict, translators
        elif type == 'number':
            value = rdict.get(name, None)
            if value is None or isinstance(value, float):
                continue
            try:
                value_float = float(value)
                rdict[name] = value_float
            except TypeError as te:
                return rdict, translators
            except ValueError as ve:
                return rdict, translators
        elif type == 'boolean':
            value = rdict.get(name, None)
            if value is None or isinstance(value, bool):
                continue
            try:
                if value == "true":
                    value_bool = True
                elif value == "false":
                    value_bool = False
                else:
                    return dict
                rdict[name] = value_bool
            except TypeError as te:
                return rdict, translators
            except ValueError as ve:
                return rdict, translators
    return rdict, translators