from services import COMMON_PORTS

def get_service(port):
    return COMMON_PORTS.get(port, "Unknown Service")