import re 
def safe_int(value):
	try: 
		return int(value)
	except (TypeError, ValueError): 
		return None
def normalize_to_list(value):
	if not value:
		return []
	return [value] if isinstance(value, dict) else value
def is_ip_address(value): 
	return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", value))