from flask import session, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user
from app import app, db
from replit_auth import require_login, make_replit_blueprint
from ip_filter import require_ip_whitelist, ip_filter
from monitoring import *
from models import User, AccessLog, IPAttempt
import json
import os

# Register auth blueprint
app.register_blueprint(make_replit_blueprint(), url_prefix="/auth")

# Make session permanent
@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/')
@require_ip_whitelist
def index():
    """Главная страница - показывает landing или dashboard в зависимости от аутентификации"""
    # Для локальной разработки пропускаем аутентификацию
    is_local_dev = os.environ.get('REPL_ID', 'local-dev-mode') == 'local-dev-mode'
    
    if not is_local_dev and not current_user.is_authenticated:
        return render_template('login.html')
    
    # Получение данных для мониторинга
    groups = get_groups()
    selected_group = request.args.get('group', groups[0] if groups else None)
    selected_subgroup = request.args.get('subgroup', 'Все')
    subgroups = get_subgroups(selected_group) if selected_group else ['Все']
    
    hosts = get_hosts(selected_group, selected_subgroup) if selected_group else []
    selected_host = request.args.get('host', hosts[0]['address'] if hosts else None)
    
    start_time = request.args.get('start_time', None)
    end_time = request.args.get('end_time', None)
    status = request.args.get('status', None)
    ping_history = get_ping_history(selected_group, selected_host, start_time, end_time, status, selected_subgroup) if selected_group and selected_host else []
    
    dashboard_data = get_dashboard_data(selected_group, selected_subgroup) if selected_group else {'availability': [], 'latency': [], 'down': []}
    
    # Получение статусов подгрупп для цветового кодирования
    subgroup_statuses = {}
    if selected_group:
        for sg in subgroups:
            if sg != 'Все':
                subgroup_statuses[sg] = get_subgroup_status_summary(selected_group, sg)
    
    # Получение статусов хостов
    host_statuses = {}
    if selected_group:
        for host in hosts:
            host_statuses[host['address']] = get_host_status_color(selected_group, host['address'])
    
    return render_template('index.html', 
                         groups=groups, 
                         selected_group=selected_group, 
                         subgroups=subgroups, 
                         selected_subgroup=selected_subgroup, 
                         hosts=hosts, 
                         selected_host=selected_host, 
                         ping_history=ping_history, 
                         dashboard_data=dashboard_data,
                         start_time=start_time,
                         end_time=end_time,
                         status=status,
                         subgroup_statuses=subgroup_statuses,
                         host_statuses=host_statuses,
                         user=current_user)

@app.route('/admin')
@require_ip_whitelist
@require_login
def admin():
    """Административная панель"""
    if not current_user.is_admin:
        flash('У вас нет прав доступа к административной панели', 'error')
        return redirect(url_for('index'))
    
    # Получение логов доступа
    access_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(100).all()
    
    # Получение заблокированных IP
    blocked_ips = IPAttempt.query.filter_by(is_blocked=True).all()
    
    # Загрузка белого списка
    whitelist = ip_filter.load_whitelist()
    blacklist = ip_filter.load_blacklist()
    
    return render_template('admin.html',
                         access_logs=access_logs,
                         blocked_ips=blocked_ips,
                         whitelist=whitelist,
                         blacklist=blacklist,
                         user=current_user)

@app.route('/admin/whitelist', methods=['POST'])
@require_ip_whitelist
@require_login
def update_whitelist():
    """Обновление белого списка IP"""
    if not current_user.is_admin:
        return jsonify({'error': 'Нет прав доступа'}), 403
    
    action = request.form.get('action')
    ip = request.form.get('ip', '').strip()
    
    if not ip:
        flash('IP адрес не может быть пустым', 'error')
        return redirect(url_for('admin'))
    
    whitelist = ip_filter.load_whitelist()
    
    if action == 'add' and ip not in whitelist:
        whitelist.append(ip)
        try:
            os.makedirs(os.path.dirname(ip_filter.whitelist_file), exist_ok=True)
            with open(ip_filter.whitelist_file, 'w') as f:
                json.dump({'allowed_ips': whitelist}, f, indent=2)
            flash(f'IP {ip} добавлен в белый список', 'success')
        except Exception as e:
            flash(f'Ошибка сохранения: {e}', 'error')
    
    elif action == 'remove' and ip in whitelist:
        whitelist.remove(ip)
        try:
            with open(ip_filter.whitelist_file, 'w') as f:
                json.dump({'allowed_ips': whitelist}, f, indent=2)
            flash(f'IP {ip} удален из белого списка', 'success')
        except Exception as e:
            flash(f'Ошибка сохранения: {e}', 'error')
    
    return redirect(url_for('admin'))

@app.route('/admin/unblock', methods=['POST'])
@require_ip_whitelist
@require_login
def unblock_ip():
    """Разблокировка IP адреса"""
    if not current_user.is_admin:
        return jsonify({'error': 'Нет прав доступа'}), 403
    
    ip = request.form.get('ip', '').strip()
    if not ip:
        flash('IP адрес не может быть пустым', 'error')
        return redirect(url_for('admin'))
    
    # Удаление из базы данных
    attempt = IPAttempt.query.filter_by(ip_address=ip).first()
    if attempt:
        db.session.delete(attempt)
        db.session.commit()
    
    # Удаление из файла черного списка
    blacklist = ip_filter.load_blacklist()
    if ip in blacklist:
        blacklist.remove(ip)
        ip_filter.save_blacklist(blacklist)
    
    flash(f'IP {ip} разблокирован', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/users')
@require_ip_whitelist
@require_login
def manage_users():
    """Управление пользователями"""
    if not current_user.is_admin:
        flash('У вас нет прав доступа', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users, user=current_user)

@app.route('/admin/users/<user_id>/toggle_admin', methods=['POST'])
@require_ip_whitelist
@require_login
def toggle_admin(user_id):
    """Переключение статуса администратора пользователя"""
    if not current_user.is_admin:
        return jsonify({'error': 'Нет прав доступа'}), 403
    
    user = User.query.get(user_id)
    if user and user.id != current_user.id:  # Нельзя изменить свой статус
        user.is_admin = not user.is_admin
        db.session.commit()
        status = 'назначен' if user.is_admin else 'снят'
        flash(f'Пользователь {user.email} {status} администратором', 'success')
    
    return redirect(url_for('manage_users'))

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

# API endpoints for AJAX requests
@app.route('/api/groups')
@require_ip_whitelist
def api_groups():
    """API endpoint для получения списка групп"""
    groups = get_groups()
    return jsonify({'groups': groups})

@app.route('/api/subgroups')
@require_ip_whitelist
def api_subgroups():
    """API endpoint для получения подгрупп"""
    group_name = request.args.get('group')
    if not group_name:
        return jsonify({'error': 'Group parameter required'}), 400
    
    subgroups = get_subgroups(group_name)
    subgroup_statuses = {}
    
    for sg in subgroups:
        if sg != 'Все':
            subgroup_statuses[sg] = get_subgroup_status_summary(group_name, sg)
    
    return jsonify({
        'subgroups': subgroups,
        'subgroup_statuses': subgroup_statuses
    })

@app.route('/api/hosts')
@require_ip_whitelist
def api_hosts():
    """API endpoint для получения хостов"""
    group_name = request.args.get('group')
    subgroup = request.args.get('subgroup', 'Все')
    
    if not group_name:
        return jsonify({'error': 'Group parameter required'}), 400
    
    hosts = get_hosts(group_name, subgroup)
    host_statuses = {}
    
    for host in hosts:
        host_statuses[host['address']] = get_host_status_color(group_name, host['address'])
    
    return jsonify({
        'hosts': hosts,
        'host_statuses': host_statuses
    })

@app.route('/api/ping_history')
@require_ip_whitelist
def api_ping_history():
    """API endpoint для получения истории пингов"""
    group_name = request.args.get('group')
    address = request.args.get('host')
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')
    status = request.args.get('status')
    subgroup = request.args.get('subgroup')
    
    if not group_name or not address:
        return jsonify({'error': 'Group and host parameters required'}), 400
    
    ping_history = get_ping_history(group_name, address, start_time, end_time, status, subgroup)
    
    return jsonify({'ping_history': ping_history})

@app.route('/api/dashboard')
@require_ip_whitelist
def api_dashboard():
    """API endpoint для получения данных дашборда"""
    group_name = request.args.get('group')
    subgroup = request.args.get('subgroup', 'Все')
    
    if not group_name:
        return jsonify({'error': 'Group parameter required'}), 400
    
    dashboard_data = get_dashboard_data(group_name, subgroup)
    
    return jsonify({'dashboard_data': dashboard_data})

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500
