from enum import Enum

class ThreatType(Enum):
    PROCESS = "PROCESS"
    FILE = "FILE"
    NETWORK = "NETWORK"
    PERSISTENCE = "PERSISTENCE"
    UNKNOWN = "UNKNOWN"