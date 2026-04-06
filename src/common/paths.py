from pathlib import Path
import yaml
CONFIG_PATH = Path(__file__).resolve().parents[2] / 'config' / 'config.yaml'
PROJECT_ROOT = CONFIG_PATH.parent.parent
with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
    cfg = yaml.safe_load(f)

def project_path(relative):
    return PROJECT_ROOT / relative
RAW_DIR = project_path(cfg['data']['raw_data_path'])
PROCESSED_DIR = project_path(cfg['data']['processed_data_path'])
VULNERABILITY_DB_DIR = project_path(cfg['data']['vulnerability_db_path'])
