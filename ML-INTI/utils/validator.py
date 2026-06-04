import ipaddress

def validate_ip(ip):

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
def get_real_ip(req):
    if req.headers.get("X-Forwarded-For"):
        return req.headers.get("X-Forwarded-For").split(",")[0].strip()
    if req.headers.get("X-Real-IP"):
        return req.headers.get("X-Real-IP")
    return req.remote_addr