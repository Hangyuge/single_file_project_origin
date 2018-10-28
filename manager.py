from flask import Flask, request, jsonify, g
from flask_script import Manager
from werkzeug.exceptions import BadRequest
from wtforms import Form, StringField, PasswordField, IntegerField, BooleanField
from wtforms import validators
from flask_migrate import Migrate, MigrateCommand
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from functools import wraps

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app=app)


# token验证装饰器
def token_required(fn):
    @wraps(fn)
    def decorator(*args, **kwargs):
        token = request.headers.get('access-token')
        if not token:  # 无令牌
            return jsonify({'status': '1', 'message': '无token令牌'})
        s = Serializer(secret_key=app.config['SECRET_KEY'])
        try:
            public_id = s.loads(token)
        except BadSignature:
            return jsonify({'status': '1', 'message': '无效token数据'})
        except SignatureExpired:
            return jsonify({'status': '1', 'message': 'token令牌过期'})
        user = UserModel.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'status': '1', 'message': '用户不存在'})
        g.user = user
        return fn(*args, **kwargs)

    return decorator


# 自定义异常, 不能返回json数据
class NoNeedJsonReturnError(Exception):
    def __init__(self, e):
        self.error_desc = e

    def __str__(self):
        return self.error_desc


# 待办事项id校验
def check_todo_id(todo_id):
    todo = ToDoListModel.query.filter_by(id=todo_id, user_id=g.user.id).first()
    if not todo:  # todo_id不属于当前用户
        raise NoNeedJsonReturnError('返回值为json数据')
    return todo


###############################################################
# 数据表
###############################################################

# 用户信息表
class UserModel(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    password = db.Column(db.String(128))
    age = db.Column(db.Integer, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    public_id = db.Column(db.String(128), unique=True)

    def keys(self):
        return 'name', 'age', 'public_id', 'is_admin'

    def __getitem__(self, item):
        if hasattr(self, item):
            return getattr(self, item)

    def set_attrs(self, data):
        for k, v in data.items():
            if hasattr(self, k) and k != 'id':
                setattr(self, k, v)


# 待办事项表
class ToDoListModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200))
    is_finished = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer)

    def keys(self):
        return 'id', 'content', 'is_finished'

    def __getitem__(self, item):
        if hasattr(self, item):
            return getattr(self, item)


migrate = Migrate(app=app, db=db)
manager = Manager(app=app)
manager.add_command('db', MigrateCommand)


#############################################################
# 表单验证
#############################################################
# 创建用户表单
class AddUserForm(Form):
    username = StringField(validators=[validators.Length(min=3, message='用户名不能小于3个字符')])
    password = PasswordField(validators=[validators.Length(min=6, message='密码不能小于6个字符')])


# 更改用户信息表单
class ChangeUserForm(AddUserForm):
    age = IntegerField(validators=[validators.NumberRange(max=150, message='年龄不科学')], default=0)
    is_admin = BooleanField(default=False)


############################################################
# 用户管理
############################################################
# 创建用户
@app.route('/user/', endpoint='add_user', methods=['POST'])
@token_required
def add_user():
    if not g.user.is_admin:  # 如果不是管理员
        return jsonify({'status': '1', 'message': '非管理员'})
    data = request.get_json()
    form = AddUserForm(data=data)
    if not form.validate():
        return jsonify({'status': '1', 'message': form.errors})
    username = data['username']
    pwd = data['password']
    password = generate_password_hash(pwd)
    user = UserModel()
    user.name = username
    user.password = password
    user.public_id = str(uuid.uuid4())
    db.session.add(user)
    db.session.commit()
    return jsonify({'status': '0', 'message': '创建用户成功'})


# 查看所有用户信息
@app.route('/user/', endpoint='show_all_users', methods=['GET'])
@token_required
def show_all_users():
    if not g.user.is_admin:  # 如果不是管理员
        return jsonify({'status': '1', 'message': '非管理员'})
    users = UserModel.query.all()
    user_list = [dict(user) for user in users]
    return jsonify({'status': '0', 'message': user_list})


# 用户登录
@app.route('/login/', endpoint='user_login', methods=['GET', 'POST'])
def user_login():
    try:
        auth = request.authorization
        username = auth.username
        password = auth.password
    except AttributeError as e:
        print(e)
        return jsonify({'status': '1', 'message': 'base64解析出错'})
    else:
        user = UserModel.query.filter_by(name=username).first()
        if user and check_password_hash(user.password, password):
            s = Serializer(secret_key=app.config['SECRET_KEY'], expires_in=12 * 60 * 60)
            data = s.dumps(user.public_id)
            return jsonify({'status': '0', 'public_id': data.decode('ascii')})
        else:
            return jsonify({'status': '1', 'message': '用户名或密码错误'})


# 查看单个用户信息
@app.route('/user/<public_id>/', endpoint='show_one_user', methods=['GET'])
def show_one_user(public_id):
    user = UserModel.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'status': '1', 'message': '无当前用户'})
    data = {'username': user.name, 'age': user.age, 'is_admin': user.is_admin, 'public_id': user.public_id}
    return jsonify({'status': '0', 'message': data})


# 删除单个用户
@app.route('/user/<public_id>/', endpoint='del_user', methods=['DELETE'])
def del_user(public_id):
    user = UserModel.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'status': '1', 'message': '无当前用户'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': '0', 'message': '用户已删除'})


# 修改用户信息
@app.route('/user/<public_id>/', endpoint='update_user', methods=['PUT'])
def update_user(public_id):
    user = UserModel.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'status': '1', 'message': '无当前用户'})
    try:
        data = request.get_json()
    except BadRequest as e:
        # print(e)
        return jsonify({'status': '1', 'message': '未提交数据'})
    form = ChangeUserForm(data=data)
    if not form.validate():
        return jsonify({'status': '1', 'message': form.errors})
    user.name = form.username.data
    user.age = form.age.data
    user.password = generate_password_hash(form.password.data)
    user.is_admin = form.is_admin.data
    db.session.add(user)
    db.session.commit()
    return jsonify({'status': '0', 'message': '用户信息已经更改'})


###################################################################
# 待办事项管理
###################################################################
# 当前用户添加待办事项
@app.route('/todo/', endpoint='create_todo', methods=['POST'])
@token_required
def create_todo():
    try:
        data = request.get_json()
    except BadRequest as e:
        # print(e)
        return jsonify({'status': '1', 'message': '未提交数据'})
    if not data.get('content'):
        return jsonify({'status': '1', 'message': '提交数据格式错误'})
    todo = ToDoListModel(content=data.get('content'), user_id=g.user.id)
    db.session.add(todo)
    db.session.commit()
    return jsonify({'status': '0', 'message': '已添加待办事项'})


# 删除某个待办事项
@app.route('/todo/<int:todo_id>/', endpoint='del_one_todo', methods=['DELETE'])
@token_required
def del_one_todo(todo_id):
    try:
        todo = check_todo_id(todo_id)
    except NoNeedJsonReturnError:  # todo返回json数据,捕获异常, 返回todo对象, 执行后面代码
        return jsonify({'status': '1', 'message': '当前用户无该事项id'})
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'status': '0', 'message': '该待办事项已被删除'})


# 更改某项事项内容
@app.route('/todo/<int:todo_id>/', endpoint='change_todo', methods=['PUT'])
@token_required
def change_todo(todo_id):
    try:
        todo = check_todo_id(todo_id)
    except NoNeedJsonReturnError:  # todo返回json数据,捕获异常, 返回todo对象, 执行后面代码
        return jsonify({'status': '1', 'message': '当前用户无该事项id'})
    try:
        data = request.get_json()
    except BadRequest as e:
        # print(e)
        return jsonify({'status': '1', 'message': '未提交数据'})
    if not data.get('content') and not data.get('is_finished'):
        return jsonify({'status': '1', 'message': '提交数据格式错误'})
    todo.content = data.get('content', '')
    todo.is_finished = data.get('is_finished', False)
    db.session.add(todo)
    db.session.commit()
    return jsonify({'status': '0', 'message': '该事项数据更改成功'})


# 查看当前用户所有待办事项
@app.route('/todo/', endpoint='show_all_todo', methods=['GET'])
@token_required
def show_all_todo():
    todos = ToDoListModel.query.filter_by(user_id=g.user.id).all()
    data = [{'id': todo.id, 'content': todo.content, 'is_finished': todo.is_finished, } for todo in todos]
    return jsonify({'status': '0', 'message': data})


if __name__ == '__main__':
    manager.run()
