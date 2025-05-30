import csv
from flask import Blueprint, render_template, redirect, url_for, flash, abort, request, make_response
from flask_login import login_required, current_user
from modeldb import VisitLog, db, User
from datetime import datetime
from sqlalchemy import func
import io
from functools import wraps

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


def check_rights(action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Требуется авторизация для доступа к данной странице.', 'warning')
                return redirect(url_for('login'))

            user_id = kwargs.get('user_id')  # Извлекаем user_id

            if not hasattr(current_user, 'role') or not current_user.role:
                # Разрешаем редактирование своего профиля, даже если нет роли
                if action == 'edit_user' and user_id == current_user.id:
                    return f(*args, **kwargs)
                flash('У вас не назначена роль.', 'warning')
                return redirect(url_for('index'))

            if current_user.role.name == 'admin':
                return f(*args, **kwargs)

            elif current_user.role.name == 'user':
                if action == 'edit_user' and user_id != current_user.id:
                    flash('Вы можете редактировать только свой профиль.', 'danger')
                    return redirect(url_for('index'))
                elif action in ('create_user', 'delete_user', 'view_all_logs', 'view_page_visits', 'view_user_visits'):
                    flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
                    return redirect(url_for('index'))
                else:
                    return f(*args, **kwargs)

            flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
            return redirect(url_for('index'))
        return decorated_function
    return decorator


@reports_bp.route('/visit_logs', methods=['GET'])
@login_required
def view_visit_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Количество записей на странице

    # Фильтрация записей в зависимости от роли
    if current_user.role and current_user.role.name == 'admin':
        logs = VisitLog.query.order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)
    else:
        logs = VisitLog.query.filter_by(user_id=current_user.id).order_by(
            VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)

    return render_template('reports/visit_logs.html', logs=logs)


@reports_bp.route('/page_visits', methods=['GET'])
@login_required
@check_rights('view_page_visits')
def page_visits():
    page_visits_data = db.session.query(
        VisitLog.path,
        func.count(VisitLog.id).label('visit_count')
    ).group_by(VisitLog.path).order_by(func.count(VisitLog.id).desc()).all()

    page_visits_list = [
        {'path': row.path, 'visit_count': row.visit_count}
        for row in page_visits_data
    ]
    start_index = 1
    return render_template('reports/page_visits.html', page_visits=page_visits_list, start_index=start_index)


@reports_bp.route('/page_visits/export_csv', methods=['GET'])
@login_required
def export_page_visits_csv():
    # Считаем статистику по страницам
    page_visits_data = db.session.query(
        VisitLog.path,
        func.count(VisitLog.id).label('visit_count')
    ).group_by(VisitLog.path).order_by(func.count(VisitLog.id).desc()).all()

    # CSV
    csv_data = [['№', 'Страница', 'Количество посещений']]
    for i, row in enumerate(page_visits_data):
        csv_data.append([i + 1, row.path, row.visit_count])

    csv_output = io.StringIO()
    csv_writer = csv.writer(csv_output)
    csv_writer.writerows(csv_data)

    response = make_response(csv_output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=page_visits.csv'
    return response


@reports_bp.route('/user_visits', methods=['GET'])
@login_required
@check_rights('view_user_visits')
def user_visits():
    user_visits_data = db.session.query(
        User.first_name,
        User.last_name,
        func.count(VisitLog.id).label('visit_count')
    ).join(User, VisitLog.user_id == User.id, isouter=True).group_by(User.id).order_by(func.count(VisitLog.id).desc()).all()

    user_visits_list = [
        {'user_info': f"{row.first_name or ''} {row.last_name or ''}", 'visit_count': row.visit_count}
        for row in user_visits_data
    ]
    start_index = 1
    return render_template('reports/user_visits.html', user_visits=user_visits_list, start_index=start_index)


@reports_bp.route('/user_visits/export_csv', methods=['GET'])
@login_required
def export_user_visits_csv():
    user_visits_data = db.session.query(
        User.first_name,
        User.last_name,
        func.count(VisitLog.id).label('visit_count')
    ).join(User, VisitLog.user_id == User.id, isouter=True).group_by(User.id).order_by(func.count(VisitLog.id).desc()).all()

    csv_data = [['№', 'Пользователь', 'Количество посещений']]
    for i, row in enumerate(user_visits_data):
        user_info = f"{row.first_name or ''} {row.last_name or ''}" or "Неаутентифицированный пользователь"
        csv_data.append([i + 1, user_info, row.visit_count])

    csv_output = io.StringIO()
    csv_writer = csv.writer(csv_output)
    csv_writer.writerows(csv_data)

    response = make_response(csv_output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=user_visits.csv'
    return response