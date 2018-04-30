import re
from datetime import datetime

def re_validator_maker(pattern):
    p = re.compile(pattern)
    def re_validator(value, tag, schema):
        if (isinstance(value, str) and not re.search(p, value)):
            return "%r does not match %r" % (value, pattern)
        else:
            return None
    return re_validator

def datetime_validator(value, tag, schema):
    if isinstance(value, str):
        try:
            datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return "Incorrect datatime format, should be YYYY-MM-DD HH:mm:SS"
    return None

def datetime_translator(value):
    return datetime.strptime(value, '%Y-%m-%d %H:%M:%S')

def date_validator(value, tag, schema):
    if isinstance(value, str):
        try:
            datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            return "Incorrect data format, should be YYYY-MM-DD"
    return None

def date_translator(value):
    return datetime.strptime(value, '%Y-%m-%d')