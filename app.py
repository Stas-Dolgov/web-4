from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from faker import Faker
from modeldb import db, User, Role  
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp, ValidationError

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dss.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)  # Инициализируем базу данных внутри приложения

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  
login_manager.login_message = "Для доступа к этой странице необходимо войти."

fake = Faker(['ru_RU']) 


def validate_password(form, field):
    password = field.data
    if not (len(password) >= 8 and len(password) <= 128):
        raise ValidationError('Пароль должен быть от 8 до 128 символов.')
    if not any(c.isupper() for c in password):
        raise ValidationError('Пароль должен содержать хотя бы одну заглавную букву.')
    if not any(c.islower() for c in password):
        raise ValidationError('Пароль должен содержать хотя бы одну строчную букву.')
    if not any(c.isdigit() for c in password):
        raise ValidationError('Пароль должен содержать хотя бы одну цифру.')
    if ' ' in password:
        raise ValidationError('Пароль не должен содержать пробелы.')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Старый пароль', validators=[DataRequired()])
    new_password = PasswordField('Новый пароль', validators=[DataRequired(), validate_password])
    confirm_new_password = PasswordField('Подтвердите новый пароль', validators=[
        DataRequired(),
        EqualTo('new_password', message='Пароли должны совпадать.')
    ])
    submit = SubmitField('Сохранить')

    def validate_old_password(self, field):
        if not check_password_hash(current_user.password_hash, field.data):
            raise ValidationError('Неверный старый пароль.')


class CreateUserForm(FlaskForm):
    username = StringField('Логин', validators=[
        DataRequired(message="Поле не может быть пустым."),
        Length(min=5, message="Логин должен быть не менее 5 символов."),
        Regexp(r'^[a-zA-Z0-9]+$', message="Логин должен состоять только из латинских букв и цифр.")
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message="Поле не может быть пустым."),
        validate_password
    ])
    confirm_password = PasswordField('Подтвердите пароль', validators=[
        DataRequired(message="Поле не может быть пустым."),
        EqualTo('password', message="Пароли должны совпадать.")
    ])
    first_name = StringField('Имя', validators=[DataRequired(message="Поле не может быть пустым.")])
    last_name = StringField('Фамилия')
    middle_name = StringField('Отчество')
    role = SelectField('Роль', choices=[(None, '------')], default=None)  
    submit = SubmitField('Сохранить')


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    form = CreateUserForm()

    # Заполняем поле выбора роли
    form.role.choices = [(None, '------')] + [(role.id, role.name) for role in Role.query.all()]

    if form.validate_on_submit():
        # Получаем данные из формы
        username = form.username.data
        password = form.password.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        middle_name = form.middle_name.data
        role_id = form.role.data if form.role.data != 'None' else None

        # Проверяем, существует ли пользователь с таким логином
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь с таким логином уже существует.', 'danger')
            return render_template('create_user.html', form=form)

        # Создаем нового пользователя
        new_user = User(username=username, first_name=first_name, last_name=last_name, middle_name=middle_name, role_id=role_id)
        new_user.set_password(password)  # Хешируем пароль
        db.session.add(new_user)
        db.session.commit()

        flash('Пользователь успешно создан!', 'success')
        return redirect(url_for('index'))  # Перенаправляем на главную страницу

    return render_template('create_user.html', form=form)


class EditUserForm(FlaskForm):
    first_name = StringField('Имя', validators=[DataRequired(message="Поле не может быть пустым.")])
    last_name = StringField('Фамилия')
    middle_name = StringField('Отчество')
    role = SelectField('Роль', choices=[(None, '------')], default=None)
    submit = SubmitField('Сохранить')


@app.route('/edit_user_submit/<int:user_id>', methods=['POST'])
@login_required
def edit_user_submit(user_id):
    user = User.query.get_or_404(user_id)

    # Получаем данные из формы
    user.first_name = request.form.get('first_name')
    user.last_name = request.form.get('last_name')
    user.middle_name = request.form.get('middle_name')
    user.role_id = request.form.get('role') if request.form.get('role') != 'None' else None

    try:
        db.session.commit()
        flash('Пользователь успешно отредактирован!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при редактировании пользователя: {str(e)}', 'danger')

    return redirect(url_for('index'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'Пользователь {user.username} удален!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')

    return redirect(url_for('index'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            flash("Вы успешно вошли!", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash("Неверный логин или пароль.", "danger")

    return render_template('login.html')


@app.route('/about')
def about():
    return render_template('about.html', title='Дополнительно')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for('login'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password_hash, form.old_password.data):
            flash('Неверный старый пароль', 'danger')
        else:
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Пароль успешно изменен!', 'success')
            return redirect(url_for('index'))
    return render_template('change_password.html', form=form)


@app.route('/')
def index():
    users = User.query.all()
    roles = Role.query.all()
    form = EditUserForm()  # Создаем экземпляр формы
    return render_template('index.html', users=users, roles=roles, form=form) 


@app.route('/create_db')
def create_db():
    with app.app_context():
        db.create_all()
    return "БД создана"


@app.route('/fill_db')
def fill_db():
    with app.app_context():
        admin_role = Role(name='admin', description='Администратор')
        db.session.add(admin_role)
        user_role = Role(name='user', description='Пользователь')
        db.session.add(user_role)

        admin = User(username='admin', first_name='Станислав', last_name='Долгов', role=admin_role)
        admin.set_password('str0ng_p@ssWORD371')
        db.session.add(admin)

        user = User(username='Vasya', first_name='Василий', last_name='Дудкин', role=user_role)
        user.set_password('beer_in_hand-m4t_0n_bOaRd')
        db.session.add(user)

        user = User(username='user', first_name='Ghosh', last_name='Kert', role=user_role)
        user.set_password('who-IS-it?9')
        db.session.add(user)

        db.session.commit()

    return "БД заполнена"


if __name__ == '__main__':
    if not os.path.exists('dss.db'):
        with app.app_context():
            db.create_all()  # Создаем таблицы
    app.run(debug=True)