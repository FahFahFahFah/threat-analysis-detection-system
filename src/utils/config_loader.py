import yaml

def get_config(path='config/config.yaml'):
    with open(path, 'r') as f:
        return yaml.safe_load(f)
