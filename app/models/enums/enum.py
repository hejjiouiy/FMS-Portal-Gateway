from enum import Enum

class UserStatusEnum(str, Enum):
    ACTIVATED = "ACTIVATED"
    INACTIVATED = "INACTIVATED"
    ARCHIVED = "ARCHIVED"


class RoleEnum(str, Enum):
    BPA = "BPA"
    CG = "CG"
    RH = "RH"
    USER = "user"
    ADMIN = "admin"

class UniteEnum(str, Enum):
    FMS = "FMS"
    SHCC = "SHCC"
    CHU = "CHU"
    UM6P = "UM6P"

class FonctionEnum(str, Enum):
    DOCTORANT = "DOCTORANT"
    POST_DOCTORANT = "POST_DOCTORANT"
    ASSISTANT_PROFESSEUR = "ASSISTANT_PROFESSEUR"
    PROFESSEUR = "PROFESSEUR"
    STAGIAIRE = "STAGIAIRE"
    PERSONNEL = "PERSONNEL"


