Config = {
    "SWAGGER": {
        "doc_root": '../doc',
        "base_url": "/api/v123456",
        # "host": "a.com:5000",
        # "schemes": "https",
        "doc_enable": True,
        "validate_enable": True,
        "enable_cors": True,
        "swagger_ui": "http://localhost:9999",
        "domain": "http://localhost:5000",

        "swagger_version": "3.0.0",
        # "swagger_version": "2.0",
        # "url_prefix": "/api/v1/apidoc",
        "info": {
            "version": "v1",
            "title": "Swagger测试",
            "description": "测试各种参数，规则"
        },
        "externalDocs": {
            "description": "了解更多文档",
            "url": 'http://blog.self.kim'
        }
    },
    # "SERVER_NAME": "127.0.0.1:5000"
}