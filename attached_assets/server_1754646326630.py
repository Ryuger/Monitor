from flask import Flask, render_template, request
import sqlite3
import pandas as pd
import netifaces
import sys

app = Flask(__name__, static_folder='static')

def get_db_connection():
    """Подключение к базе данных SQLite."""
    conn = sqlite3.connect("monitoring.db")
    conn.row_factory = sqlite3.Row
    return conn

def get_groups():
    """Получение списка групп из базы данных."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT group_name FROM groups")
    groups = [row['group_name'] for row in cursor.fetchall()]
    conn.close()
    return groups

def get_subgroups(group_name):
    """Получение списка подгрупп в группе."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(f"SELECT DISTINCT subgroup FROM hosts_{group_name} WHERE subgroup IS NOT NULL")
        subgroups = [row['subgroup'] for row in cursor.fetchall()]
        return ['Все'] + subgroups if subgroups else ['Все']
    except sqlite3.Error:
        return ['Все']
    finally:
        conn.close()

def get_hosts(group_name, subgroup=None):
    """Получение списка хостов в группе с фильтром по подгруппе."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = f"SELECT address, description, subgroup FROM hosts_{group_name}"
        params = []
        if subgroup and subgroup != 'Все':
            query += " WHERE subgroup = ?"
            params.append(subgroup)
        cursor.execute(query, params)
        hosts = [{'address': row['address'], 'description': row['description'], 'subgroup': row['subgroup'] or 'нет'} for row in cursor.fetchall()]
    except sqlite3.Error:
        hosts = []
    conn.close()
    return hosts

def get_ping_history(group_name, address, start_time=None, end_time=None, status=None, subgroup=None):
    """Получение истории пингов для хоста с фильтром по подгруппе."""
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT timestamp, status, latency FROM ping_results WHERE group_name = ? AND address = ?"
    params = [group_name, address]
    
    if start_time:
        query += " AND timestamp >= ?"
        params.append(start_time)
    if end_time:
        query += " AND timestamp <= ?"
        params.append(end_time)
    if status:
        query += " AND status = ?"
        params.append(status)
    if subgroup and subgroup != 'Все':
        cursor.execute(f"SELECT subgroup FROM hosts_{group_name} WHERE address = ?", (address,))
        host_subgroup = cursor.fetchone()
        if host_subgroup and host_subgroup[0] != subgroup:
            return []
    
    query += " ORDER BY timestamp"
    cursor.execute(query, params)
    history = [{'timestamp': row['timestamp'], 'status': row['status'], 'latency': row['latency'] if row['latency'] is not None else 'нет данных'} for row in cursor.fetchall()]
    conn.close()
    return history

def get_dashboard_data(group_name, subgroup=None):
    """Получение данных для дашборда с фильтром по подгруппе."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Процент доступности хостов
    query = f"SELECT address FROM hosts_{group_name}"
    params = []
    if subgroup and subgroup != 'Все':
        query += " WHERE subgroup = ?"
        params.append(subgroup)
    cursor.execute(query, params)
    hosts = [row['address'] for row in cursor.fetchall()]
    availability_data = []
    for address in hosts:
        cursor.execute(
            "SELECT status, COUNT(*) as count FROM ping_results WHERE group_name = ? AND address = ? GROUP BY status",
            (group_name, address)
        )
        total = 0
        up_count = 0
        for row in cursor.fetchall():
            total += row['count']
            if row['status'] == 'Доступен':
                up_count += row['count']
        availability = (up_count / total * 100) if total > 0 else 0
        availability_data.append({'address': address, 'availability': round(availability, 2)})
    
    # Средняя задержка для доступных хостов
    query = "SELECT address, AVG(latency) as avg_latency FROM ping_results WHERE group_name = ? AND status = 'Доступен' GROUP BY address"
    params = [group_name]
    if subgroup and subgroup != 'Все':
        cursor.execute(f"SELECT address FROM hosts_{group_name} WHERE subgroup = ?", (subgroup,))
        host_addresses = [row[0] for row in cursor.fetchall()]
        if host_addresses:
            query += " AND address IN ({})".format(','.join('?' * len(host_addresses)))
            params.extend(host_addresses)
    cursor.execute(query, params)
    latency_data = [{'address': row['address'], 'avg_latency': round(row['avg_latency'], 3) if row['avg_latency'] is not None else 0} for row in cursor.fetchall()]
    
    # Количество недоступных хостов по времени
    query = "SELECT timestamp, COUNT(*) as down_count FROM ping_results WHERE group_name = ? AND status = 'Недоступен' GROUP BY timestamp"
    params = [group_name]
    if subgroup and subgroup != 'Все':
        cursor.execute(f"SELECT address FROM hosts_{group_name} WHERE subgroup = ?", (subgroup,))
        host_addresses = [row[0] for row in cursor.fetchall()]
        if host_addresses:
            query += " AND address IN ({})".format(','.join('?' * len(host_addresses)))
            params.extend(host_addresses)
    cursor.execute(query, params)
    down_data = [{'timestamp': row['timestamp'], 'down_count': row['down_count']} for row in cursor.fetchall()]
    
    conn.close()
    return {'availability': availability_data, 'latency': latency_data, 'down': down_data}

def get_network_interfaces():
    """Получение списка сетевых интерфейсов и их IP-адресов."""
    interfaces = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                netmask = addr['netmask']
                interfaces.append({
                    'name': iface,
                    'ip': ip,
                    'netmask': netmask,
                    'id': iface if iface != 'lo' else 'lo'
                })
    return interfaces

def select_network_interface():
    """Запрос у пользователя выбора сетевого интерфейса."""
    interfaces = get_network_interfaces()
    if not interfaces:
        print("Ошибка: Не найдены сетевые интерфейсы.")
        sys.exit(1)
    
    print("\n=== Система мониторинга хостов ===")
    print("Выберите сетевой интерфейс для запуска сервера:\n")
    
    for i, iface in enumerate(interfaces, 1):
        if iface['name'] == 'lo':
            print(f"{i}. {iface['id']} - {iface['ip']} (Localhost (только локальный доступ))")
        else:
            print(f"{i}. {iface['id']} - {iface['ip']} (IPv4: {iface['ip']}/{iface['netmask']})")
    
    while True:
        try:
            choice = int(input("\nВведите номер интерфейса (1-{}): ".format(len(interfaces))))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice-1]['ip']
            else:
                print(f"Неверный выбор. Пожалуйста, выберите число от 1 до {len(interfaces)}.")
        except ValueError:
            print("Ошибка: Введите число.")

@app.route('/')
def index():
    """Главная страница с вкладками по подгруппам."""
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
                         status=status)

if __name__ == '__main__':
    selected_ip = select_network_interface()
    print(f"\nЗапуск сервера на IP: {selected_ip}...")
    app.run(host=selected_ip, debug=True, use_reloader=False)