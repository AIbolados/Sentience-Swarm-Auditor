import hashlib
import os
import json

STATE_FILE = "/home/jibol2/swarm_auditor/state.json"

def get_dir_hash(directory):
    hash_func = hashlib.md5()
    for root, dirs, files in os.walk(directory):
        # Ignorar carpetas pesadas/inútiles para el hash
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv'}]
        for names in sorted(files):
            filepath = os.path.join(root, names)
            try:
                with open(filepath, 'rb') as f:
                    while chunk := f.read(8192):
                        hash_func.update(chunk)
            except:
                pass
    return hash_func.hexdigest()

def has_changed(project_name, project_path):
    current_hash = get_dir_hash(project_path)
    
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            state = json.load(f)
    else:
        state = {}
        
    old_hash = state.get(project_name)
    
    if current_hash != old_hash:
        state[project_name] = current_hash
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
        return True
    
    return False

if __name__ == "__main__":
    # Test simple
    print(has_changed("test", "/home/jibol2/swarm_auditor"))
