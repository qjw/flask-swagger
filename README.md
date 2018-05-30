本项目用于自动生成swagger文档定义，需要配合额外的swagger ui使用，主要特性包括

1. 支持json/yml定义文档，且均支持`文件内`/`跨文件`引用，支持`跨格式引用`
1. 支持`自动校验`和`自动转换`。文档和校验分开，可单独启用
1. 支持单个view多endpoint/method分别定义文档
1. 支持扩展自带的校验/转换规则
1. 支持swaggerui分别部署，内建跨域支持

# 运行Sample
```
virtualenv -p python3 venv
. venv/bin/activate
pip install -r requirements.txt
export FLASK_APP="sample/app.py"
flask run
```
访问<http://localhost:5000/apidoc>即可测试

## PIP安装
``` bash
# 安装dev分支
pip install git+https://github.com/qjw/flask-swagger.git@dev
pip install git+ssh://git@github.com/qjw/flask-swagger.git@dev
# 安装版本（tag）
pip install git+https://github.com/qjw/flask-swagger.git@v1.0.0
pip install git+ssh://git@github.com/qjw/flask-swagger.git@v1.0.0
```

# 使用
``` python
swagger = Swagger()
if __name__=='__main__':
    app = Flask(__name__)
    app.config.update(Config or {})

    @app.errorhandler(jsonschema.ValidationError)
    def handle_bad_request(e):
        return make_response(jsonify(code=400,
                 message=e.schema.get('error', '参数校验错误'),
                 details=e.message,
                 schema=str(e.schema)), 200)

    swagger.init_app(app)
```
``` python
Config = {
    "SWAGGER": {
        "doc_root": '../doc',
        "doc_enable": True,
        "swagger_ui": "http://localhost:9999",
    }
}
```
``` python
@api.route('/helloworld')
@swagger.doc('doc.json#/helloworld')
def helloworld():
    return jsonify(code=0, message='ok')

@api.route('/yaml_sample')
@swagger.doc('doc.yml#/yaml_sample')
def yaml_sample():
    return jsonify(code=0, message='ok')
```

## 定义文档

推荐一个json/yml文档定义多个API

``` json
{
    "helloworld": {
        "summary": "hello world",
        "description": "这只是个简单的实例",
        "tags": [
            "基础"
        ],
        "responses": {
            "200": {
                "schema": {
                    "properties": {
                    }
                }
            }
        }
    }
}
```

或者 yml格式

`yml支持多行，所以在备注时写markdown很方便`

``` yml
yaml_sample:
  summary: 使用yaml格式
  description: |
      # 使用yml格式写doc
      1. aaaa
      2. bbb
  tags:
    - 其他
  parameters:
    - name: id
      in: query
      type: integer
      description: 联系人ID
    - name: name
      in: query
      type: string
      description: 联系人名字
  responses:
    200:
      schema:
        properties:
          code:
            type: integer
            description: 返回码
            default: 0
```

## 单文档
也可以对单个API使用独立的(json/yml)文件定义
``` python
@api.route('/standalone', methods=["PUT","DELETE"])
@swagger.doc('standalone.yml', methods=["PUT"])
@swagger.doc('standalone.json', methods=["DELETE"])
def standalone():
    return jsonify(code=0, message='ok')
```
``` json
{
    "summary": "独立文件作为doc/json",
    "tags": [
        "其他"
    ],
    "responses": {
        "200": {
            "schema": {
                "properties": {
                    "data": {
                        "$ref": "file:definitions.yml#/car"
                    },
                    "data2": {
                        "$ref": "file:definitions.json#/user"
                    }
                }
            }
        }
    }
}
```

下面的文档支持
1. json/yml互引用
1. json/yml均支持跨文件引用

``` yml
summary: "独立文件作为doc/yaml"
tags:
  - "其他"
parameters:
  - name: id
    in: path
    type: integer
    required: true
responses:
  200:
    schema:
      properties:
        data:
          $ref: "file:definitions.yml#/car"
        data2:
          $ref: "file:definitions.json#/user"
```

# Parameters

支持query参数，path参数，json格式和普通的form

json格式的in为body，下面的schema存在一个对当前文件[**#definitions/update**]的引用

``` json
[
    {
        "name": "name",
        "in": "formData",
        "type": "string",
        "description": "联系人名字",
        "required": true
    },
    {
        "name": "id",
        "in": "path",
        "type": "integer",
        "description": "联系人ID",
        "required": true
    },
    {
        "in": "body",
        "name":"body",
        "description": "需要修改的内容",
        "required": true,
        "schema": {
            "type": "object",
            "properties": {
                "default": {
                    "type": "boolean",
                    "description": "是否设置默认",
                    "default":true
                },
                "contact": {
                    "$ref": "#/definitions/update"
                }
            },
            "required": [
                "contact"
            ]
        }
    },
    {
        "name": "page",
        "in": "query",
        "type": "integer",
        "description": "页码",
        "required": true
    }
]
```

## 访问参数
在flask中，query参数和form参数中所有的value都是string类型，若doc声明类型为[integer],flasgger内部会自动转换成int。最终的结果存放在

1. json - request.json_dict (老版本是request.json)
2. formData/form - request.form_dict
3. query - request.query_dict
4. path - request.view_args

``` python
@api.route('/form', methods=["POST"])
@swagger.doc('doc.json#/form')
def form():
    return jsonify(code=0, message='ok',data={
        "f1": request.form_dict["f1"],
        "f2": request.form_dict["f2"]
    })
```
``` python
@api.route('/json', methods=["PUT"])
@swagger.doc('doc.json#/json')
def json():
    return jsonify(code=0, message='ok',data=request.json)
```
``` python
@api.route('/params/<int:id>', methods=["PATCH"])
@swagger.doc('doc.json#/params')
def params(id):
    return jsonify(code=0, message='ok',data={
        "json": request.json,
        "id": id,
        "query1": request.query_dict.get("query1",None),
        "query2": request.query_dict["query2"],
    })
```

# 文档引用
跨文件引用多种格式
``` python
summary: "独立文件作为doc/yaml"
tags:
  - "其他"
parameters:
  - name: id
    in: path
    type: integer
    required: true
responses:
  200:
    schema:
      properties:
        data:
          $ref: "file:definitions.yml#/car"
        data2:
          $ref: "file:definitions.json#/user"
```
引用同文件部分
``` python
{
    "group": {
        "summary": "分组/oneof",
        "description": "三组中任意一种",
        "tags": [
            "对象复用"
        ],
        "parameters": [
            {
                "in": "body",
                "name": "body",
                "required": true,
                "schema": {
                    "type": "object",
                    "oneOf": [{
                        "$ref": "#/group/definitions/a"
                    }, {
                        "$ref": "#/group/definitions/b"
                    }]
                }
            }
        ],
        "definitions": {
            "a": {
                "type": "object",
                "properties": {
                    "a1": {
                        "type": "string",
                        "default": "a1"
                    },
                    "a2": {
                        "type": "string",
                        "default": "a2"
                    }
                }
            },
            "b": {
                "type": "object",
                "properties": {
                    "b1": {
                        "type": "string",
                        "default": "b1"
                    },
                    "b2": {
                        "type": "string",
                        "default": "b2"
                    }
                }
            }
        }
    }
}
```

# 多endpoint/method

下面的例子

1. 路由/endpoints GET/POST分别使用一套文档
2. 路由/endpoint/<int:id> 所有的HTTP方法都使用相同的文档

``` python
@api.route('/endpoints', defaults={'id': None}, endpoint="endpoints", methods=["GET","POST"])
@api.route('/endpoint/<int:id>', endpoint="endpoint", methods=["PUT","DELETE"])
@swagger.doc('doc.yml#/endpoints_get', endpoint="endpoints", blueprint=api, methods=["GET"])
@swagger.doc('doc.yml#/endpoints_post', endpoint="endpoints", blueprint=api, methods=["POST"])
@swagger.doc('doc.yml#/endpoint_all', endpoint="endpoint", blueprint=api)
def endpoint_method(id):
    return jsonify(code=0, message='ok')
```


## MethodView
``` python
# Method View
class UserAPI(MethodView):
    decorators = [
        swagger.doc('doc.yml#/method_view')
    ]
    def get(self):
        return jsonify(code=0, message='ok')

api.add_url_rule('/method_view',view_func=UserAPI.as_view('user_method_view'))
```


# 自定义校验方法
使用注解`swagger.validator`，**注意swagger是新建的对象实例**
``` python
@swagger.validator("hm")
def hour_minute_validator(value, tag, schema):
    if isinstance(value, str):
        try:
            datetime.strptime(value, '%H:%M')
        except ValueError:
            return "Incorrect hour-minute format, should be hh:mm"
    return None
```

## 手动注册
``` python
swagger.register_validator("hm", hour_minute_validator)
```

## 翻译器
对于一些特殊的变量，比如日期，通常传入字符串(2018-04-10)，但实际逻辑中往往需要转换成Datetime对象。翻译器可以自动完成

`body(json)变量不支持翻译器`

``` python
@swagger.translator("hm")
def hour_minute_translator(value):
    try:
        inst = datetime.strptime(value, '%H:%M')
        delta = timedelta(hours=inst.hour, minutes=inst.minute)
        return delta.seconds
    except ValueError as e:
        raise e
```
``` python
swagger.register_translator("hml", hour_minute_translator)
```

## 内建校验器/翻译器
``` python
class Swagger:
    DATETIME = 'datetime'
    DATE = 'date'
    VIN = 'vin'
    PLATE = 'plate'
    MOBILE = 'mobile'
```

默认全部注册进来，其中`Datetime/Date`带翻译器

``` python
_validator_dict = {
    Swagger.DATETIME: [datetime_validator, datetime_translator],
    Swagger.DATE: [date_validator, date_translator],
    Swagger.VIN: [re_validator_maker("^[A-HJ-NPR-Z\\d]{8}[\\dX][A-HJ-NPR-Z\\d]{8}$"), None],
    Swagger.PLATE: [re_validator_maker("^[\u4e00-\u9fa5]{1}[A-Z]{1}[A-Z0-9]{4,5}[A-Z0-9\u4e00-\u9fa5]$"), None],
    Swagger.MOBILE: [re_validator_maker("^1[3|4|5|8][0-9]{9}$"), None],
}
```

可以在初始化时，选择需要注入的内建翻译器
``` python
swagger.init_app(app, validators=[
    Swagger.DATE
])
```

## 使用
注意标签`validator： hm`
``` yml
custome_validator:
  summary: 自定义校验
  tags:
    - 校验
  parameters:
    - name: time
      in: formData
      type: string
      validator: hm
      default: "09:30"
      description: "日期（时/分）（09:30）"
      required: true
    - name: mobile
      in: formData
      type: string
      validator: mobile
```

## 覆盖重写
自定义和内建的校验器/翻译器共享同一命名空间，所以tag不能重复，后面注入的会覆盖之前的定义，所以可以用此方法重写内建方法

例如不想让Datetime自动转换，可以

``` python
@swagger.translator("datetime")
def datetime_translator(value):
    return value
```


## 配置

```python
Config = {
    SWAGGER: {
        "doc_root": '../doc/json',
        "base_url": "/api/v1",
        "info":
            {
                "version": "v1",
                "title": "swagger",
                "description": "swagger document"
            }
        },
        "url_prefix": "apidoc"
}
```
``` python
app = Flask(__name__)
app.config.update(Config or {})
```

### doc_root
定义文档根目录，可以相对路径或者绝对路径，相对路径基于**app.root_path**，当没有跨文件引用，该参数可以不设置

### base_url
定义所有api的base地址，默认`/`。通常API都会以诸如**/api/v1**之类的开头，定义本变量的好处在于，swagger文档页不会显示这个前缀，例如接口/api/v1/me/default会显示/me/default，但是提交时，会自动附上base_url已确保提交测试URL的正确。

### info
版本，标题和描述

1. version : 版本号
2. title: 文档标题，例如XX公司YY模块文档
3. description: 文档简介

### url_prefix
默认是`/apidoc`，用来定义访问文档的地址，通常配合下面两个变量使用

1. swagger_ui: UI的地址，由于本项目不自带swagger ui，所以需要明确指定地址，若涉及到跨域问题，参见`enable_cors`选项
2. domain: 本机的地址（包含schema/host/port），在访问`url_prefix`时，会自动跳转到`swagger_ui`，并且当前服务器地址（`使用本参数`）会作为跳转参数，以便swagger ui能正确获取spec。

以下面的配置为例，访问<http://localhost:5000/apidoc>会自动跳转到<http://localhost:9999/index.html?url=http://localhost:5000/apidoc/spec>。（`spec是自动加上`）
``` python
Config = {
    "SWAGGER": {
        "swagger_ui": "http://localhost:9999",
        "domain": "http://localhost:5000"
    }
}
```
### swagger_ui/domain
参见`url_prefix`

## 测试API
若存在跨域问题，需要被测试接口开启cors，或者代理到同域

下面的参数可以控制提交的URL

1. schemes: 使用Http还是Https
2. host: 使用其他域名，例如hosts增加`a.com 127.0.0.1`

``` python
Config = {
    "SWAGGER": {
        "schemes": "http",
        "host": "a.com:5000",
    }
}
```

> 关于api的通用前缀，参见`base_url参数`

## 不做校验
swagger.doc注解添加【**validate_flag=False**】参数即可禁用校验，只保留doc

```
@api.route('/14', methods=['GET'])
@swagger.doc('api.json#/14',validate_flag=False)
def f14():
    return jsonify(code=0, message='ok')
```

## 校验错误处理
定义全局错误处理函数，留意**handle_bad_request**

> schema可以定义key为**error**的string字段，用于自定义错误输出
为了方便调试，开发环境建议将**schema打印出来**

```python
@app.errorhandler(jsonschema.ValidationError)
def handle_bad_request(e):
  return make_response(jsonify(code=400,
                               message=e.schema.get('error', '参数校验错误'),
                               details=e.message,
                               schema=str(e.schema)), 200)
```

## 文档和校验配置
默认开启文档和校验，可以通过全局和局部配置修改选项

swagger.doc参数validate_flag可以单独关闭api的自动校验
```python
@api.route('/contact',methods=['PUT'])
@swagger.doc('doc/doc.json#/api',validate_flag=False)
def disable_validate():
    return jsonify(code=0, message='ok', data={})
```

> validate_flag优先级`高于`全局配置validate_enable

可以使用下面的全局配置定义`文档`（**默认关闭**）和`校验`（**默认开启**） 默认开启属性
```python
SWAGGER = {
    "validate_enable":True,
    "doc_enable":False
    }
```

## 跨域
和flasgger不同，本项目并不集成swagger ui，若从其他域的html访问spec，浏览器会出现跨域错误，通过`enable_cors`选项（默认开启）可以支持跨域（*仅限doc相关的几个API*）。

## 自定义错误提示

> 留意error key的字段以及**handle_bad_request**处理函数

```json
{
    "in": "body",
    "name":"body",
    "description": "需要修改的内容",
    "required": true,
    "schema": {
        "type": "object",
        "properties": {
            "description": {
                "type": "string",
                "description": "需要修改的内容",
                "maxLength": 140,
                "error": "限140字"
            }
        },
        "required":[
            "description"
        ]
    }
}
```

错误处理

```python
@app.errorhandler(jsonschema.ValidationError)
def handle_bad_request(e):
  return make_response(jsonify(code=400,
                               message=e.schema.get('error', '参数校验错误'),
                               details=e.message,
                               schema=str(e.schema)), 200)
```


# 参考
原始需求参考 <https://github.com/rochacbruno/flasgger>

因为不太符合个人需求，fork并做修改后的版本在<https://github.com/qjw/flasgger>

主要的修改含：

1. 跨文件引用(格式yml->json)
1. 自动jsonscheme校验
1. 原来单文件定义API改成一个文件定义多个API
1. 文档cache，提高启动效率
1. 基本类型转换，比如string -> int等
1. 注入自定义校验规则