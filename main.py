from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
import requests
import json
import os
from collections import OrderedDict
import copy
import threading
import time
import io
import csv
import uuid
from datetime import datetime, timedelta

try:
    from jsonschema import validate, ValidationError
except ImportError:
    validate = None
    ValidationError = None

app = Flask(__name__)
app.secret_key = 'firebase_rtdb_editor_secret_key_change_in_production'

# Add custom filter for JSON in templates
@app.template_filter('tojson')
def tojson_filter(obj):
    return json.dumps(obj)

# Store data globally (in production, use proper session management or database)
app_data = {
    'original_data': {},
    'live_data_on_fetch': {},
    'url_profiles': {},
    'json_schema': None,
    'search_results': [],
    'current_search_index': 0
}

# Define login credentials and their associated tiers
CREDENTIALS = {
    "hey_silver": {"password": "view_data", "tier": "Silver Edition"},
    "hey_gold": {"password": "edit_data", "tier": "Gold Edition"},
    "hey_elite": {"password": "elite_data", "tier": "Elite Edition"},
    "admin": {"password": "admin123", "tier": "Elite Edition", "is_admin": True}
}

# Enhanced admin data storage with resale system
ADMIN_DATA = {
    'users': [
        {"username": "hey_silver", "tier": "Silver Edition", "status": "active", "email": "silver@demo.com", "role": "user", "credits": 0},
        {"username": "hey_gold", "tier": "Gold Edition", "status": "active", "email": "gold@demo.com", "role": "user", "credits": 0},
        {"username": "hey_elite", "tier": "Elite Edition", "status": "active", "email": "elite@demo.com", "role": "user", "credits": 0}
    ],
    'referrals': [
        {"code": "WELCOME2024", "used": 45, "limit": 100, "tier": "Gold Edition", "status": "active", "creator": "admin", "commission_rate": 10},
        {"code": "ELITE2024", "used": 12, "limit": 25, "tier": "Elite Edition", "status": "active", "creator": "admin", "commission_rate": 15}
    ],
    'subscriptions': {
        "Silver Edition": {"price": 0, "features": ["View Only Access"]},
        "Gold Edition": {"price": 9.99, "features": ["Edit Access", "Export Data"]},
        "Elite Edition": {"price": 19.99, "features": ["Full Access", "Admin Panel", "API Access"]}
    },
    'resellers': [
        {"username": "demo_reseller", "status": "approved", "commission_rate": 15, "credits": 100, "earnings": {"pending": 45.50, "paid": 120.00}, "platforms": ["telegram", "discord"]}
    ],
    'reseller_requests': [
        {"username": "pending_user", "request_date": "2024-01-15", "status": "pending", "message": "I want to become a reseller"}
    ],
    'chats': [],
    'sales': []
}

# Load pricelist
def load_pricelist():
    try:
        with open('config/pricelist.json', 'r') as f:
            return json.load(f)
    except:
        return {}

PRICELIST = load_pricelist()

URL_PROFILES_FILE = "firebase_urls.json"

def load_url_profiles():
    """Loads URL profiles from a JSON file."""
    if os.path.exists(URL_PROFILES_FILE):
        try:
            with open(URL_PROFILES_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_url_profiles(profiles):
    """Saves URL profiles to a JSON file."""
    try:
        with open(URL_PROFILES_FILE, 'w') as f:
            json.dump(profiles, f, indent=4)
        return True
    except Exception:
        return False

def get_value_by_path(data, path):
    """Retrieves a value from a nested dict/list using a Firebase-style path."""
    if not path:
        return data

    current_data = data
    parts = path.split('/')
    for part in parts:
        if part.startswith('[') and part.endswith(']'):
            try:
                index = int(part[1:-1])
                if isinstance(current_data, list) and 0 <= index < len(current_data):
                    current_data = current_data[index]
                else:
                    return None
            except (ValueError, TypeError):
                return None
        else:
            if isinstance(current_data, dict) and part in current_data:
                current_data = current_data[part]
            else:
                return None
    return current_data

def set_value_by_path(data, path, new_value):
    """Sets a value in a nested dict/list using a Firebase-style path."""
    if not path:
        return new_value

    parts = path.split('/')
    current_data = data

    for part in parts[:-1]:
        if part.startswith('[') and part.endswith(']'):
            try:
                index = int(part[1:-1])
                if isinstance(current_data, list) and 0 <= index < len(current_data):
                    current_data = current_data[index]
                else:
                    raise IndexError(f"Intermediate path does not exist: {part}")
            except (ValueError, TypeError):
                raise ValueError(f"Invalid list index in path: {part}")
        else:
            if isinstance(current_data, dict) and part in current_data:
                current_data = current_data[part]
            else:
                raise KeyError(f"Intermediate path does not exist: {part}")

    last_part = parts[-1]
    if last_part.startswith('[') and last_part.endswith(']'):
        try:
            index = int(last_part[1:-1])
            if isinstance(current_data, list) and 0 <= index < len(current_data):
                current_data[index] = new_value
            else:
                raise IndexError(f"Final index out of bounds: {last_part}")
        except (ValueError, TypeError):
            raise ValueError(f"Invalid final list index in path: {last_part}")
    else:
        if isinstance(current_data, dict):
            current_data[last_part] = new_value
        else:
            raise TypeError(f"Cannot set key '{last_part}' on a non-dictionary.")

    return data

def delete_value_by_path(data, path):
    """Deletes a value from a nested dict/list using a Firebase-style path."""
    if not path:
        return {}

    parts = path.split('/')
    current_data = data

    for part in parts[:-1]:
        if part.startswith('[') and part.endswith(']'):
            try:
                index = int(part[1:-1])
                current_data = current_data[index]
            except (IndexError, ValueError, TypeError):
                raise LookupError(f"Could not find path to delete: {part}")
        else:
            try:
                current_data = current_data[part]
            except (KeyError, TypeError):
                raise LookupError(f"Could not find path to delete: {part}")

    last_part = parts[-1]
    if last_part.startswith('[') and last_part.endswith(']'):
        try:
            index = int(last_part[1:-1])
            del current_data[index]
        except (IndexError, ValueError, TypeError):
            raise LookupError(f"Could not delete item at index: {last_part}")
    else:
        try:
            del current_data[last_part]
        except (KeyError, TypeError):
            raise LookupError(f"Could not delete item with key: {last_part}")

    return data

def find_diffs(old_obj, new_obj, path=""):
    """Recursively finds differences between two JSON-like objects."""
    changes = []

    if type(old_obj) != type(new_obj) or not (isinstance(old_obj, (dict, list)) and isinstance(new_obj, (dict, list))):
        if old_obj != new_obj:
            changes.append((path, new_obj))
        return changes

    if isinstance(old_obj, dict) and isinstance(new_obj, dict):
        for key, new_value in new_obj.items():
            current_path = f"{path}/{key}" if path else key
            if key not in old_obj:
                changes.append((current_path, new_value))
            else:
                changes.extend(find_diffs(old_obj[key], new_value, current_path))

        for key in old_obj.keys():
            if key not in new_obj:
                changes.append((f"{path}/{key}" if path else key, None))

    elif isinstance(old_obj, list) and isinstance(new_obj, list):
        if json.dumps(old_obj, sort_keys=True) != json.dumps(new_obj, sort_keys=True):
            changes.append((path, new_obj))

    return changes

def build_tree_structure(data, path=""):
    """Builds a tree structure for web display."""
    if isinstance(data, dict):
        children = []
        for key, value in sorted(data.items()):
            current_path = f"{path}/{key}" if path else key
            if isinstance(value, (dict, list)):
                children.append({
                    'key': key,
                    'path': current_path,
                    'type': 'container',
                    'value': '',
                    'children': build_tree_structure(value, current_path)
                })
            else:
                children.append({
                    'key': key,
                    'path': current_path,
                    'type': 'value',
                    'value': str(value),
                    'children': []
                })
        return children
    elif isinstance(data, list):
        children = []
        for i, value in enumerate(data):
            current_path = f"{path}/[{i}]"
            if isinstance(value, (dict, list)):
                children.append({
                    'key': f"[{i}]",
                    'path': current_path,
                    'type': 'container',
                    'value': '',
                    'children': build_tree_structure(value, current_path)
                })
            else:
                children.append({
                    'key': f"[{i}]",
                    'path': current_path,
                    'type': 'value',
                    'value': str(value),
                    'children': []
                })
        return children
    return []

def get_user_role(username):
    """Get user role for resale system"""
    if username == "admin":
        return "admin"

    for reseller in ADMIN_DATA['resellers']:
        if reseller['username'] == username and reseller['status'] == 'approved':
            return "reseller"

    return "user"

@app.route('/')
def index():
    if 'user_tier' not in session:
        return redirect(url_for('login'))

    app_data['url_profiles'] = load_url_profiles()
    tree_data = build_tree_structure(app_data['original_data'])

    user_role = get_user_role(session.get('username', ''))

    return render_template('index.html', 
                         tier=session['user_tier'],
                         tree_data=tree_data,
                         url_profiles=list(app_data['url_profiles'].keys()),
                         has_schema=app_data['json_schema'] is not None,
                         has_validate=validate is not None,
                         user_role=user_role,
                         pricelist=PRICELIST)

@app.route('/resale')
def resale_system():
    if 'user_tier' not in session:
        return redirect(url_for('login'))
    
    user_role = get_user_role(session.get('username', ''))
    
    return render_template('resale_system.html',
                         tier=session['user_tier'],
                         user_role=user_role,
                         pricelist=PRICELIST)

@app.route('/profile')
def profile():
    if 'user_tier' not in session:
        return redirect(url_for('login'))
    
    return render_template('profile.html',
                         tier=session['user_tier'],
                         username=session.get('username', ''))

@app.route('/admin')
def admin_panel():
    if 'user_tier' not in session or not session.get('is_admin', False):
        return redirect(url_for('login'))
    
    return render_template('admin_panel.html',
                         tier=session['user_tier'])

@app.route('/settings')
def settings():
    if 'user_tier' not in session:
        return redirect(url_for('login'))
    
    return render_template('settings.html',
                         tier=session['user_tier'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if username in CREDENTIALS and CREDENTIALS[username]["password"] == password:
            session['user_tier'] = CREDENTIALS[username]["tier"]
            session['username'] = username
            session['is_admin'] = CREDENTIALS[username].get("is_admin", False)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get('username', '').strip()
    email = request.json.get('email', '').strip()
    password = request.json.get('password', '').strip()
    referral_code = request.json.get('referral_code', '').strip()

    if not all([username, email, password, referral_code]):
        return jsonify({'success': False, 'error': 'All fields including referral code are required'})

    if username in CREDENTIALS:
        return jsonify({'success': False, 'error': 'Username already exists'})

    # Validate referral code
    referral = None
    for ref in ADMIN_DATA['referrals']:
        if ref['code'] == referral_code and ref['status'] == 'active':
            if ref['used'] < ref['limit']:
                referral = ref
                break

    if not referral:
        return jsonify({'success': False, 'error': 'Invalid or expired referral code'})

    # Create user account
    tier = referral['tier']
    CREDENTIALS[username] = {"password": password, "tier": tier}
    ADMIN_DATA['users'].append({
        "username": username,
        "tier": tier,
        "status": "active",
        "email": email,
        "role": "user",
        "credits": 0,
        "referred_by": referral['creator'],
        "signup_date": datetime.now().isoformat()
    })

    # Update referral usage
    referral['used'] += 1

    # Add commission to referrer if it's a reseller
    for reseller in ADMIN_DATA['resellers']:
        if reseller['username'] == referral['creator']:
            commission = PRICELIST.get(tier.lower().split()[0], {}).get('30', {}).get('user_price', 0) * (referral['commission_rate'] / 100)
            reseller['earnings']['pending'] += commission
            ADMIN_DATA['sales'].append({
                "id": str(uuid.uuid4()),
                "referrer": referral['creator'],
                "user": username,
                "tier": tier,
                "commission": commission,
                "date": datetime.now().isoformat(),
                "status": "pending"
            })
            break

    return jsonify({'success': True, 'message': f'Account created successfully with {tier}'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Resale System API Routes

@app.route('/api/resale/request_reseller', methods=['POST'])
def request_reseller():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})

    username = session['username']
    message = request.json.get('message', '')

    # Check if already a reseller or has pending request
    for reseller in ADMIN_DATA['resellers']:
        if reseller['username'] == username:
            return jsonify({'success': False, 'error': 'You are already a reseller'})

    for req in ADMIN_DATA['reseller_requests']:
        if req['username'] == username and req['status'] == 'pending':
            return jsonify({'success': False, 'error': 'You already have a pending request'})

    ADMIN_DATA['reseller_requests'].append({
        "username": username,
        "request_date": datetime.now().isoformat(),
        "status": "pending",
        "message": message
    })

    return jsonify({'success': True, 'message': 'Reseller request submitted successfully'})

@app.route('/api/resale/resellers', methods=['GET'])
def get_resellers():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})

    return jsonify({
        'success': True,
        'resellers': [r for r in ADMIN_DATA['resellers'] if r['status'] == 'approved']
    })

@app.route('/api/resale/dashboard/<username>')
def reseller_dashboard(username):
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})

    current_user = session['username']
    if current_user != username and not session.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Unauthorized'})

    reseller = None
    for r in ADMIN_DATA['resellers']:
        if r['username'] == username:
            reseller = r
            break

    if not reseller:
        return jsonify({'success': False, 'error': 'Reseller not found'})

    # Get referral stats
    user_referrals = [u for u in ADMIN_DATA['users'] if u.get('referred_by') == username]
    referral_codes = [r for r in ADMIN_DATA['referrals'] if r['creator'] == username]

    return jsonify({
        'success': True,
        'dashboard': {
            'stats': {
                'users_referred': len(user_referrals),
                'earnings': reseller['earnings'],
                'commission_rate': reseller['commission_rate'],
                'credits': reseller['credits']
            },
            'referral_codes': referral_codes,
            'referred_users': user_referrals
        }
    })

@app.route('/api/resale/create_referral', methods=['POST'])
def create_referral_code():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})

    username = session['username']
    user_role = get_user_role(username)

    if user_role not in ['reseller', 'admin']:
        return jsonify({'success': False, 'error': 'Reseller access required'})

    code = request.json.get('code', '').strip()
    tier = request.json.get('tier', 'Silver Edition')
    limit = request.json.get('limit', 100)
    commission_rate = request.json.get('commission_rate', 10)

    if not code:
        return jsonify({'success': False, 'error': 'Referral code is required'})

    # Check if code already exists
    for ref in ADMIN_DATA['referrals']:
        if ref['code'] == code:
            return jsonify({'success': False, 'error': 'Referral code already exists'})

    ADMIN_DATA['referrals'].append({
        "code": code,
        "used": 0,
        "limit": limit,
        "tier": tier,
        "status": "active",
        "creator": username,
        "commission_rate": commission_rate,
        "created_date": datetime.now().isoformat()
    })

    return jsonify({'success': True, 'message': 'Referral code created successfully'})

@app.route('/api/resale/admin/approve_reseller', methods=['POST'])
def approve_reseller():
    if not session.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Admin access required'})

    username = request.json.get('username', '')
    action = request.json.get('action', 'approve')  # approve or deny

    # Find and update request
    for req in ADMIN_DATA['reseller_requests']:
        if req['username'] == username and req['status'] == 'pending':
            req['status'] = action + 'd'

            if action == 'approve':
                # Add to resellers
                ADMIN_DATA['resellers'].append({
                    "username": username,
                    "status": "approved",
                    "commission_rate": 10,
                    "credits": 0,
                    "earnings": {"pending": 0, "paid": 0},
                    "platforms": [],
                    "approved_date": datetime.now().isoformat()
                })

            return jsonify({'success': True, 'message': f'Reseller request {action}d successfully'})

    return jsonify({'success': False, 'error': 'Request not found'})

@app.route('/api/resale/admin/manage_credits', methods=['POST'])
def manage_credits():
    if not session.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Admin access required'})

    username = request.json.get('username', '')
    action = request.json.get('action', 'add')  # add or deduct
    amount = request.json.get('amount', 0)

    for reseller in ADMIN_DATA['resellers']:
        if reseller['username'] == username:
            if action == 'add':
                reseller['credits'] += amount
            else:
                reseller['credits'] = max(0, reseller['credits'] - amount)

            return jsonify({'success': True, 'message': f'Credits {action}ed successfully'})

    return jsonify({'success': False, 'error': 'Reseller not found'})

@app.route('/api/resale/chat/send', methods=['POST'])
def send_chat_message():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})

    sender = session['username']
    recipient = request.json.get('recipient', '')
    message = request.json.get('message', '').strip()

    if not message:
        return jsonify({'success': False, 'error': 'Message cannot be empty'})

    chat_message = {
        "id": str(uuid.uuid4()),
        "sender": sender,
        "recipient": recipient,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "read": False
    }

    ADMIN_DATA['chats'].append(chat_message)

    return jsonify({'success': True, 'message': 'Message sent successfully'})

@app.route('/api/resale/chat/get/<recipient>')
def get_chat_messages(recipient):
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})

    username = session['username']

    messages = [
        chat for chat in ADMIN_DATA['chats']
        if (chat['sender'] == username and chat['recipient'] == recipient) or
           (chat['sender'] == recipient and chat['recipient'] == username)
    ]

    # Mark messages as read
    for chat in ADMIN_DATA['chats']:
        if chat['sender'] == recipient and chat['recipient'] == username:
            chat['read'] = True

    return jsonify({'success': True, 'messages': sorted(messages, key=lambda x: x['timestamp'])})

# Keep all existing API routes (fetch_data, update_node, etc.)...
@app.route('/api/fetch_data', methods=['POST'])
def fetch_data():
    if 'user_tier' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})

    url = request.json.get('url', '').strip()
    if not url or "your-project-id" in url:
        return jsonify({'success': False, 'error': 'Please enter a valid Firebase URL'})

    try:
        cleaned_base_url = url.rstrip('/')
        full_url = f"{cleaned_base_url}/.json"

        response = requests.get(full_url, timeout=10)
        response.raise_for_status()

        data = response.json(object_pairs_hook=OrderedDict)
        app_data['original_data'] = data if data is not None else OrderedDict()
        app_data['live_data_on_fetch'] = copy.deepcopy(app_data['original_data'])

        tree_data = build_tree_structure(app_data['original_data'])

        return jsonify({
            'success': True, 
            'tree_data': tree_data,
            'message': 'Data fetched successfully!'
        })

    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'error': f'Network error: {e}'})
    except json.JSONDecodeError:
        return jsonify({'success': False, 'error': 'Invalid JSON response from server'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'An unexpected error occurred: {e}'})

@app.route('/api/get_node_value', methods=['POST'])
def get_node_value():
    if 'user_tier' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})

    path = request.json.get('path', '')
    node_value = get_value_by_path(app_data['original_data'], path)

    if isinstance(node_value, (dict, list)):
        value_str = json.dumps(node_value, indent=4)
    elif node_value is None:
        value_str = "null"
    else:
        value_str = str(node_value)

    return jsonify({
        'success': True,
        'value': value_str,
        'path': f"/{path}" if path else "/"
    })

@app.route('/api/update_node', methods=['POST'])
def update_node():
    if 'user_tier' not in session or session['user_tier'] == 'Silver Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Gold or Elite Edition required.'})

    path = request.json.get('path', '')
    new_value_str = request.json.get('value', '').strip()

    try:
        try:
            new_value = json.loads(new_value_str)
        except json.JSONDecodeError:
            if new_value_str.lower() == "true": 
                new_value = True
            elif new_value_str.lower() == "false": 
                new_value = False
            elif new_value_str.lower() == "null": 
                new_value = None
            else:
                try: 
                    new_value = int(new_value_str)
                except ValueError:
                    try: 
                        new_value = float(new_value_str)
                    except ValueError: 
                        new_value = new_value_str

        temp_data = copy.deepcopy(app_data['original_data'])
        if not path:
            temp_data = new_value
        else:
            temp_data = set_value_by_path(temp_data, path, new_value)

        app_data['original_data'] = temp_data
        tree_data = build_tree_structure(app_data['original_data'])

        return jsonify({
            'success': True,
            'tree_data': tree_data,
            'message': f"Node updated. Click 'Apply Changes' to sync with Firebase."
        })

    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to update node: {e}'})

# Add remaining API routes for completeness...
@app.route('/api/apply_changes', methods=['POST'])
def apply_changes():
    if 'user_tier' not in session or session['user_tier'] == 'Silver Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Gold or Elite Edition required.'})

    url = request.json.get('url', '').strip()

    try:
        response = requests.get(f"{url.rstrip('/')}/.json", timeout=10)
        response.raise_for_status()
        current_live_data = response.json(object_pairs_hook=OrderedDict) or OrderedDict()

        if app_data['original_data'] == current_live_data:
            return jsonify({'success': False, 'error': 'No changes detected to apply'})

        changes = find_diffs(current_live_data, app_data['original_data'])

        if not changes:
            return jsonify({'success': False, 'error': 'No changes detected to apply'})

        # Apply changes via Firebase REST API
        patch_payload = {path: value for path, value in changes if path != ""}
        if patch_payload:
            response = requests.patch(f"{url.rstrip('/')}/.json", json=patch_payload, timeout=10)
            response.raise_for_status()
            message = f"Successfully applied {len(patch_payload)} change(s)."

        app_data['live_data_on_fetch'] = copy.deepcopy(app_data['original_data'])

        return jsonify({
            'success': True,
            'message': message
        })

    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'error': f'Failed to apply changes: {e}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'An unexpected error occurred: {e}'})

@app.route('/api/add_child', methods=['POST'])
def add_child():
    if 'user_tier' not in session or session['user_tier'] == 'Silver Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Gold or Elite Edition required.'})
    
    path = request.json.get('path', '')
    key = request.json.get('key', '').strip()
    value_str = request.json.get('value', '').strip()
    
    try:
        parent_node = get_value_by_path(app_data['original_data'], path)
        new_data = copy.deepcopy(app_data['original_data'])
        
        if isinstance(parent_node, dict):
            if not key:
                return jsonify({'success': False, 'error': 'Key is required for object'})
            if key in parent_node:
                return jsonify({'success': False, 'error': f'Key "{key}" already exists'})
            
            try:
                value = json.loads(value_str)
            except json.JSONDecodeError:
                value = value_str
            
            new_child_path = f"{path}/{key}" if path else key
            set_value_by_path(new_data, new_child_path, value)
            
        elif isinstance(parent_node, list):
            try:
                value = json.loads(value_str)
            except json.JSONDecodeError as e:
                return jsonify({'success': False, 'error': f'Invalid JSON for array item: {e}'})
            
            modifiable_parent = get_value_by_path(new_data, path)
            modifiable_parent.append(value)
        else:
            return jsonify({'success': False, 'error': 'Can only add children to objects or arrays'})
        
        app_data['original_data'] = new_data
        tree_data = build_tree_structure(app_data['original_data'])
        
        return jsonify({
            'success': True,
            'tree_data': tree_data,
            'message': f"Added child to /{path}. Click 'Apply Changes' to sync."
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to add child: {e}'})

@app.route('/api/delete_node', methods=['POST'])
def delete_node():
    if 'user_tier' not in session or session['user_tier'] == 'Silver Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Gold or Elite Edition required.'})
    
    path = request.json.get('path', '')
    
    try:
        app_data['original_data'] = delete_value_by_path(copy.deepcopy(app_data['original_data']), path)
        tree_data = build_tree_structure(app_data['original_data'])
        
        return jsonify({
            'success': True,
            'tree_data': tree_data,
            'message': f"Node /{path} deleted. Click 'Apply Changes' to sync."
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to delete node: {e}'})

@app.route('/api/duplicate_node', methods=['POST'])
def duplicate_node():
    if 'user_tier' not in session or session['user_tier'] == 'Silver Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Gold or Elite Edition required.'})
    
    path = request.json.get('path', '')
    new_key = request.json.get('new_key', '').strip()
    
    try:
        node_value = copy.deepcopy(get_value_by_path(app_data['original_data'], path))
        path_parts = path.split('/') if path else []
        parent_path = '/'.join(path_parts[:-1]) if len(path_parts) > 1 else ''
        parent_node = get_value_by_path(app_data['original_data'], parent_path)
        new_data = copy.deepcopy(app_data['original_data'])
        
        if isinstance(parent_node, dict):
            if not new_key:
                return jsonify({'success': False, 'error': 'New key is required for object'})
            if new_key in parent_node:
                return jsonify({'success': False, 'error': f'Key "{new_key}" already exists'})
            
            new_full_path = f"{parent_path}/{new_key}" if parent_path else new_key
            set_value_by_path(new_data, new_full_path, node_value)
            
        elif isinstance(parent_node, list):
            modifiable_parent = get_value_by_path(new_data, parent_path)
            modifiable_parent.append(node_value)
        else:
            return jsonify({'success': False, 'error': 'Can only duplicate nodes within objects or arrays'})
        
        app_data['original_data'] = new_data
        tree_data = build_tree_structure(app_data['original_data'])
        
        return jsonify({
            'success': True,
            'tree_data': tree_data,
            'message': f"Duplicated node. Click 'Apply Changes' to sync."
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to duplicate node: {e}'})

@app.route('/api/push_item', methods=['POST'])
def push_item():
    if 'user_tier' not in session or session['user_tier'] != 'Elite Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Elite Edition required.'})
    
    url = request.json.get('url', '').strip()
    path = request.json.get('path', '')
    item_content_str = request.json.get('content', '').strip()
    
    try:
        item_content = json.loads(item_content_str)
        full_url = f"{url.rstrip('/')}/{path}.json"
        
        response = requests.post(full_url, json=item_content, timeout=10)
        response.raise_for_status()
        pushed_key = response.json().get("name", "N/A")
        
        return jsonify({
            'success': True,
            'message': f"Pushed new item with key: {pushed_key}"
        })
        
    except json.JSONDecodeError as e:
        return jsonify({'success': False, 'error': f'Invalid JSON content: {e}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error pushing new item: {e}'})

@app.route('/api/search', methods=['POST'])
def search():
    if 'user_tier' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    search_term = request.json.get('term', '').strip().lower()
    
    if not search_term:
        return jsonify({'success': False, 'error': 'Please enter a search term'})
    
    results = []
    
    def search_recursive(data, path=""):
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}/{key}" if path else key
                if search_term in key.lower():
                    results.append({'path': current_path, 'key': key, 'match_type': 'key'})
                if isinstance(value, str) and search_term in str(value).lower():
                    results.append({'path': current_path, 'key': key, 'match_type': 'value'})
                if isinstance(value, (dict, list)):
                    search_recursive(value, current_path)
        elif isinstance(data, list):
            for i, value in enumerate(data):
                current_path = f"{path}/[{i}]"
                if isinstance(value, str) and search_term in str(value).lower():
                    results.append({'path': current_path, 'key': f"[{i}]", 'match_type': 'value'})
                if isinstance(value, (dict, list)):
                    search_recursive(value, current_path)
    
    search_recursive(app_data['original_data'])
    app_data['search_results'] = results
    app_data['current_search_index'] = 0
    
    if not results:
        return jsonify({'success': False, 'error': f'No occurrences of "{search_term}" found'})
    
    return jsonify({
        'success': True,
        'results': results,
        'total': len(results),
        'message': f'Found {len(results)} occurrence(s) of "{search_term}"'
    })

@app.route('/api/url_profiles', methods=['GET', 'POST', 'DELETE'])
def url_profiles():
    if 'user_tier' not in session or session['user_tier'] != 'Elite Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Elite Edition required.'})
    
    profiles = load_url_profiles()
    
    if request.method == 'GET':
        return jsonify({'success': True, 'profiles': profiles})
    
    elif request.method == 'POST':
        name = request.json.get('name', '').strip()
        url = request.json.get('url', '').strip()
        
        if not name or not url:
            return jsonify({'success': False, 'error': 'Name and URL are required'})
        
        if name in profiles:
            return jsonify({'success': False, 'error': f'Profile "{name}" already exists'})
        
        profiles[name] = url
        if save_url_profiles(profiles):
            return jsonify({'success': True, 'message': f'URL profile "{name}" added'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save URL profile'})
    
    elif request.method == 'DELETE':
        name = request.json.get('name', '').strip()
        
        if name not in profiles:
            return jsonify({'success': False, 'error': 'Profile not found'})
        
        del profiles[name]
        if save_url_profiles(profiles):
            return jsonify({'success': True, 'message': f'URL profile "{name}" removed'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save URL profiles'})

@app.route('/api/save_data', methods=['POST'])
def save_data():
    if 'user_tier' not in session or session['user_tier'] != 'Elite Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Elite Edition required.'})
    
    if not app_data['original_data']:
        return jsonify({'success': False, 'error': 'No data to save'})
    
    try:
        filename = f"firebase_data_{int(time.time())}.json"
        filepath = os.path.join('/tmp', filename)
        
        with open(filepath, 'w') as f:
            json.dump(app_data['original_data'], f, indent=4)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to save data: {e}'})

@app.route('/api/export_data', methods=['POST'])
def export_data():
    if 'user_tier' not in session or session['user_tier'] != 'Elite Edition':
        return jsonify({'success': False, 'error': 'Feature locked. Elite Edition required.'})
    
    export_format = request.json.get('format', 'json').lower()
    
    if not app_data['original_data']:
        return jsonify({'success': False, 'error': 'No data to export'})
    
    try:
        filename = f"firebase_data_{int(time.time())}.{export_format}"
        filepath = os.path.join('/tmp', filename)
        
        if export_format == 'json':
            with open(filepath, 'w') as f:
                json.dump(app_data['original_data'], f, indent=4)
        elif export_format == 'csv':
            if isinstance(app_data['original_data'], list) and all(isinstance(item, dict) for item in app_data['original_data']):
                if not app_data['original_data']:
                    raise ValueError("Cannot export empty list to CSV.")
                
                all_keys = set()
                for item in app_data['original_data']:
                    all_keys.update(item.keys())
                headers = sorted(list(all_keys))
                
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(app_data['original_data'])
            else:
                raise TypeError("CSV export is only supported for a flat list of objects.")
        else:
            return jsonify({'success': False, 'error': 'Unsupported export format'})
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to export data: {e}'})

@app.route('/api/load_schema', methods=['POST'])
def load_schema():
    if 'user_tier' not in session or session['user_tier'] != 'Elite Edition' or not validate:
        return jsonify({'success': False, 'error': 'Feature locked. Elite Edition required and jsonschema library needed.'})
    
    if 'schema_file' not in request.files:
        return jsonify({'success': False, 'error': 'No schema file provided'})
    
    file = request.files['schema_file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    try:
        schema_content = file.read().decode('utf-8')
        app_data['json_schema'] = json.loads(schema_content)
        return jsonify({'success': True, 'message': f'JSON Schema loaded from {file.filename}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Could not load schema: {e}'})

@app.route('/api/validate_schema', methods=['POST'])
def validate_schema():
    if 'user_tier' not in session or session['user_tier'] != 'Elite Edition' or not validate:
        return jsonify({'success': False, 'error': 'Feature locked. Elite Edition required and jsonschema library needed.'})
    
    if not app_data['json_schema']:
        return jsonify({'success': False, 'error': 'No schema loaded'})
    
    if not app_data['original_data']:
        return jsonify({'success': False, 'error': 'No data to validate'})
    
    try:
        validate(instance=app_data['original_data'], schema=app_data['json_schema'])
        return jsonify({'success': True, 'message': 'Data is valid against the loaded schema!'})
    except ValidationError as e:
        error_path = "root" + "".join([f"[{p}]" if isinstance(p, int) else f".{p}" for p in e.path])
        return jsonify({'success': False, 'error': f'Validation failed: {e.message}\nAt path: {error_path}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Validation error: {e}'})

@app.route('/api/admin/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
def admin_users():
    if 'user_tier' not in session or not session.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    if request.method == 'GET':
        return jsonify({'success': True, 'users': ADMIN_DATA['users']})
    
    elif request.method == 'POST':
        username = request.json.get('username', '').strip()
        password = request.json.get('password', '').strip()
        tier = request.json.get('tier', '')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'})
        
        if username in CREDENTIALS:
            return jsonify({'success': False, 'error': 'Username already exists'})
        
        CREDENTIALS[username] = {"password": password, "tier": tier}
        ADMIN_DATA['users'].append({
            "username": username,
            "tier": tier,
            "status": "active",
            "email": f"{username}@demo.com"
        })
        
        return jsonify({'success': True, 'message': f'User {username} created successfully'})
    
    elif request.method == 'DELETE':
        username = request.json.get('username', '').strip()
        
        if username not in CREDENTIALS:
            return jsonify({'success': False, 'error': 'User not found'})
        
        del CREDENTIALS[username]
        ADMIN_DATA['users'] = [u for u in ADMIN_DATA['users'] if u['username'] != username]
        
        return jsonify({'success': True, 'message': f'User {username} deleted successfully'})

@app.route('/api/admin/referrals', methods=['GET', 'POST'])
def admin_referrals():
    if 'user_tier' not in session or not session.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    if request.method == 'GET':
        return jsonify({'success': True, 'referrals': ADMIN_DATA['referrals']})
    
    elif request.method == 'POST':
        code = request.json.get('code', '').strip()
        limit = request.json.get('limit', 100)
        tier = request.json.get('tier', 'Silver Edition')
        
        if not code:
            return jsonify({'success': False, 'error': 'Referral code required'})
        
        # Check if code already exists
        for ref in ADMIN_DATA['referrals']:
            if ref['code'] == code:
                return jsonify({'success': False, 'error': 'Referral code already exists'})
        
        ADMIN_DATA['referrals'].append({
            "code": code,
            "used": 0,
            "limit": limit,
            "tier": tier,
            "status": "active"
        })
        
        return jsonify({'success': True, 'message': f'Referral code {code} created successfully'})

@app.route('/api/profile', methods=['GET', 'PUT'])
def user_profile():
    if 'user_tier' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    username = session.get('username', 'demo_user')
    
    if request.method == 'GET':
        # Find user in admin data or create default profile
        user_data = None
        for user in ADMIN_DATA['users']:
            if user['username'] == username:
                user_data = user
                break
        
        if not user_data:
            user_data = {
                "username": username,
                "tier": session['user_tier'],
                "email": f"{username}@demo.com",
                "api_key": "fdb_" + username + "_demo_key"
            }
        
        return jsonify({'success': True, 'profile': user_data})
    
    elif request.method == 'PUT':
        email = request.json.get('email', '').strip()
        password = request.json.get('password', '').strip()
        
        # Update user data in admin storage
        for user in ADMIN_DATA['users']:
            if user['username'] == username:
                if email:
                    user['email'] = email
                break
        
        # Update password in credentials if provided
        if password and username in CREDENTIALS:
            CREDENTIALS[username]['password'] = password
        
        return jsonify({'success': True, 'message': 'Profile updated successfully'})

@app.route('/api/theme', methods=['GET', 'POST'])
def user_theme():
    if 'user_tier' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    if request.method == 'GET':
        theme = session.get('theme', 'default')
        return jsonify({'success': True, 'theme': theme})
    
    elif request.method == 'POST':
        theme = request.json.get('theme', 'default')
        session['theme'] = theme
        return jsonify({'success': True, 'message': 'Theme updated'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)