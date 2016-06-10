from flask import render_template, request, jsonify
from . import main

"""
    在蓝本中编写错误处理程序稍有不同，如果使用errorhandler修饰器，
    那么只有蓝本中的错误才能触发处理程序。要想注册程序全局的错误处理程序，
    必须使用app_errorhandler.
"""


@main.app_errorhandler(404)
def page_not_found(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        response = jsonify({'error': 'not found'})
        response.status_code = 404
        return response
    return render_template('404.html', error=e)


@main.app_errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=e)
