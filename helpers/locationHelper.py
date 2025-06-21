import json
import urllib.request

from common.log import logUtils as log
from objects import glob


def getCountry(ip):
    """
    Get country from IP address using ip.zxq.co API

    :param ip: IP address
    :return: country code. XX if invalid.
    """
    try:
        # Get country directly from the /country endpoint
        result = urllib.request.urlopen(f"https://ip.zxq.co/{ip}/country", timeout=3).read().decode()
        return result.upper()
    except:
        log.error("Error in get country")
        return "XX"

def getLocation(ip):
    """
    Get latitude and longitude from IP address using ip.zxq.co API

    :param ip: IP address
    :return: (latitude, longitude)
    """
    try:
        # Get full location data
        data = json.loads(urllib.request.urlopen(f"https://ip.zxq.co/{ip}", timeout=3).read().decode())
        
        # Parse the "loc" field which contains comma-separated latitude and longitude
        if "loc" in data and data["loc"]:
            coords = data["loc"].split(",")
            return float(coords[0]), float(coords[1])
        else:
            log.warning(f"No location data found for IP {ip}")
            return 0, 0
    except Exception as e:
        log.error(f"Error in get position: {e}")
        return 0, 0
