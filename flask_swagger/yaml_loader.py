import json
import sys
import yaml

PY3 = sys.version_info[0] >= 3

if PY3:
    from urllib import parse as urlparse
    from urllib.parse import unquote
    from urllib.request import urlopen
    unicode = str
    basestring = str
else:
    import urlparse
    from urllib import unquote
    from urllib2 import urlopen

class YamlLoader(object):
    def __init__(self):
        pass

    def __call__(self, uri, **kwargs):
        return self.get_remote_json(uri, **kwargs)

    def get_remote_json(self, uri, **kwargs):
        scheme = urlparse.urlsplit(uri).scheme
        if scheme != "file":
            raise Exception("can not support schema '%s'"%(scheme))

        # 后缀
        ftype = uri.split('.')[-1]
        if ftype == "json":
            return json.loads(urlopen(uri).read().decode("utf-8"), **kwargs)
        elif ftype == "yml" or ftype == "yaml":
            return yaml.load(urlopen(uri).read().decode("utf-8"), **kwargs)
        else:
            raise Exception("can not support file type '%s'"%(ftype))