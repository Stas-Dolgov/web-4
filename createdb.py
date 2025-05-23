from app import app, db
from modeldb import Role, User
from werkzeug.security import generate_password_hash
with app.app_context():
    db.create_all()

    # Создаем роль
    admin_role = Role(name='admin', description='Администратор')
    user_role = Role(name='user', description='Обычный пользователь')
    db.session.add_all([admin_role, user_role])
    db.session.commit()

    # Создаем пользователей
    admin = User(username='admin', password_hash=generate_password_hash('admin'), first_name='Админ', last_name='Админов', role_id=admin_role.id)
    user = User(username='user', password_hash=generate_password_hash('user'), first_name='Пользователь', last_name='Пользователев', role_id=user_role.id)
    db.session.add_all([admin, user])
    db.session.commit()

    print("База данных создана и заполнена!")
