from dataclasses import dataclass


@dataclass
class OktaUserType:
    """Models an Okta User type."""

    id: str  # pylint: disable=invalid-name
    display_name: str
    name: str
    description: str
    schemas: list
    is_default: bool

    def __init__(self, data):
        self.id = data.get('id')
        self.display_name = data.get('displayName')
        self.name = data.get('name')
        self.description = data.get('description')
        self.schemas = data.get('schemas')
        self.is_default = data.get('isDefault')


class OktaUser:  # pylint: disable=too-few-public-methods
    """Models an Okta user based on input data."""

    def __new__(cls, data):
        if data.get('profile'):
            return OktaUserActivate(data)
        return OktaUserSearch(data)


@dataclass
class OktaUserSearch:
    """Models an Okta User from search request."""

    id: str  # pylint: disable=invalid-name
    first_name: str
    last_name: str
    login: str
    email: str
    status: str
    status_code: str

    def __init__(self, data):
        self.id = data.get('id')
        self.first_name = data.get('firstName')
        self.last_name = data.get('lastName')
        self.login = data.get('login')
        self.email = data.get('email')
        self.status = data.get('status')
        self.status_code = data.get('statusCode')


@dataclass
class OktaUserActivate:
    """Models an Okta User from activate request."""

    id: str  # pylint: disable=invalid-name
    first_name: str
    last_name: str
    login: str
    email: str
    status: str
    status_code: str

    def __init__(self, data):
        self.id = data.get('id')
        self.first_name = data.get('profile').get('firstName')
        self.last_name = data.get('profile').get('lastName')
        self.login = data.get('profile').get('login')
        self.email = data.get('profile').get('email')
        self.status = data.get('status')
        self.status_code = data.get('status')


@dataclass
class UsersDataStructure:
    """Models an Active Directory User Search Result Data."""

    user_id: str
    unknown1: bool
    unknown2: str
    unknown3: bool
    user_data: dict
    assignments: list
    unknown4: bool


@dataclass
class ADUserAssignment:
    """Models an Active Directory User Assignment."""

    # pylint: disable=too-many-instance-attributes
    # Eight is reasonable in this case.

    action: str
    match_type: str
    user_id: str
    first_name: str
    last_name: str
    login: str
    email: str
    current: bool

    def __init__(self, data):
        self.action = data.get('action')
        self.match_type = data.get('matchType')
        self.user_id = data.get('userId')
        self.first_name = data.get('firstName')
        self.last_name = data.get('lastName')
        self.login = data.get('login')
        self.email = data.get('email')
        self.current = data.get('current')


@dataclass
class ADUser:
    """Models Active Directory User."""

    id: str  # pylint: disable=invalid-name
    first_name: str
    last_name: str
    user_name: str
    email: str
    assignments: list

    def __init__(self, data):
        self.id = data.user_id
        self.first_name = data.user_data.get('firstName')
        self.last_name = data.user_data.get('lastName')
        self.user_name = data.user_data.get('userName')
        self.email = data.user_data.get('email')
        self.assignments = [ADUserAssignment(assignment) for assignment in data.assignments]
