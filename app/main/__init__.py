from flask import Blueprint

main = Blueprint('main', __name__)

from . import views, errors
from ..models import Permission


@main.app_context_processor
def inject_permissions():
    """
    为了避免每次调用render_template()时都要添加一个模板参数,
    这里使用了上下文处理器,它能让变量在所有模板中全局可访问。
    """
    return dict(Permission=Permission)