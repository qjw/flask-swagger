from setuptools import setup, find_packages

setup(
    name='flask_swagger',
    version='1.0.0',
    description='swagger for flask',
    author='King Qiu',
    url='https://github.com/qjw/python-swagger',
    author_email='qiujinwu@gmail.com',
    license='MIT',
    packages=find_packages(exclude=["sample*"]),
    include_package_data=False,
    zip_safe=True,
    install_requires=[
        'Flask>=0.10',
        'flask-cors==3.0.4',
        'PyYAML>=3.0',
        'jsonschema==2.5.1',
        'jsonref==0.1'
    ]
)