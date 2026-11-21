"""PostgreSQL accounts, enterprise and project memberships, and invitations."""

from datetime import timedelta, timezone
from hashlib import sha256
from secrets import token_urlsafe
from uuid import uuid4

from production_store import DEFAULT_PROJECT, initialize_workflow


ORGANIZATION_ROLES = ("member", "moderator", "owner")
PROJECT_ROLES = ("reader", "editor", "manager")
ACCOUNT = 'username, display_name AS "displayName", password_hash AS "passwordHash", avatar'
INVITATION = """
    invite.id, invite.organization_id AS "organizationId", invite.project_id AS "projectId",
    invite.organization_role AS "organizationRole", invite.project_role AS "projectRole",
    invite.created_by AS "createdBy", invite.created_at AS "createdAt", invite.expires_at AS "expiresAt"
"""
PENDING = "invite.accepted_at IS NULL AND invite.revoked_at IS NULL AND invite.expires_at > clock_timestamp()"
PROJECT_ACCESS = """
    SELECT project.id, project.name, organization.id AS "organizationId",
        organization.name AS "organizationName", org_member.role AS "organizationRole",
        CASE WHEN principal.super_admin OR org_member.role = 'owner' THEN 'manager'
            ELSE project_member.role END AS role
    FROM bank_project AS project
    JOIN bank_organization AS organization ON organization.id = project.organization_id
    CROSS JOIN (SELECT %s::text AS username, %s::boolean AS super_admin) AS principal
    LEFT JOIN bank_organization_member AS org_member
        ON org_member.organization_id = organization.id AND org_member.username = principal.username
    LEFT JOIN bank_project_member AS project_member
        ON project_member.project_id = project.id AND project_member.username = principal.username
    WHERE (principal.super_admin OR org_member.role = 'owner' OR project_member.role IS NOT NULL)
"""


class MembershipConflict(ValueError):
    pass


def _audit(db, organization_id, project_id, actor, action, subject):
    db.execute(
        """
        INSERT INTO bank_audit_event (organization_id, project_id, actor, action, subject)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (organization_id, project_id, actor, action, subject),
    )


def _lock_organization(db, organization_id):
    return db.execute(
        "SELECT id FROM bank_organization WHERE id = %s FOR UPDATE", (organization_id,),
    ).fetchone()


def _invite_times(row):
    if row:
        for key in ("createdAt", "expiresAt"):
            row[key] = row[key].astimezone(timezone.utc).isoformat()
    return row


def _invite_digest(token):
    return sha256(token.encode("utf-8")).hexdigest()


def _validate_role(role, roles):
    if role not in roles:
        raise MembershipConflict("Указана недопустимая роль.")


def _insert_account(db, username, display_name, password_hash, policy_version):
    from case_legal import DOCUMENTS, POLICY_VERSION
    if policy_version != POLICY_VERSION:
        raise ValueError("Account registration requires the displayed document version.")
    account = db.execute(
        """
        INSERT INTO bank_account (username, display_name, password_hash) VALUES (%s, %s, %s)
        ON CONFLICT (username) DO NOTHING RETURNING username
        """,
        (username, display_name, password_hash),
    ).fetchone()
    if not account:
        raise MembershipConflict("Такой логин уже существует. Войдите в эту учётную запись.")
    db.execute("INSERT INTO bank_account_agreement(username,document,version) "
               "SELECT %s, unnest(%s::text[]), %s", (username, list(DOCUMENTS), policy_version))


def _insert_organization(db, name, actor):
    organization_id = uuid4().hex
    db.execute("INSERT INTO bank_organization (id, name) VALUES (%s, %s)", (organization_id, name))
    db.execute(
        "INSERT INTO bank_organization_member (organization_id, username, role) VALUES (%s, %s, 'owner')",
        (organization_id, actor),
    )
    _audit(db, organization_id, None, actor, "organization.create", organization_id)
    return organization_id


def _insert_project(db, organization_id, name, actor, spec, timestamp):
    project_id = uuid4().hex
    db.execute(
        "INSERT INTO bank_project (id, organization_id, name) VALUES (%s, %s, %s)",
        (project_id, organization_id, name),
    )
    db.execute(
        "INSERT INTO bank_project_member (project_id, organization_id, username, role) VALUES (%s, %s, %s, 'manager')",
        (project_id, organization_id, actor),
    )
    initialize_workflow(db, project_id, spec, timestamp)
    _audit(db, organization_id, project_id, actor, "project.create", project_id)
    return project_id


class OrganizationStore:
    def __init__(self, store):
        self.store = store

    def get_account(self, username):
        with self.store.connect() as db:
            return db.execute(f"SELECT {ACCOUNT} FROM bank_account WHERE username = %s", (username,)).fetchone()

    def update_profile(self, username, name, avatar, replace_avatar):
        with self.store.connect() as db:
            return db.execute(f"""UPDATE bank_account SET display_name=%s,
                avatar=CASE WHEN %s THEN %s ELSE avatar END WHERE username=%s RETURNING {ACCOUNT}""",
                (name, replace_avatar, avatar, username)).fetchone()

    def ensure_actor(self, username, display_name=None):
        with self.store.connect() as db:
            db.execute(
                "INSERT INTO bank_account (username, display_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (username, display_name or username),
            )
            return db.execute(f"SELECT {ACCOUNT} FROM bank_account WHERE username = %s", (username,)).fetchone()

    def seed_legacy_membership(self, username, organization_role="member", project_role="reader"):
        _validate_role(organization_role, ORGANIZATION_ROLES)
        _validate_role(project_role, PROJECT_ROLES)
        with self.store.connect() as db:
            _lock_organization(db, DEFAULT_PROJECT)
            unseeded = db.execute(
                """
                UPDATE bank_account SET legacy_membership_seeded = true
                WHERE username = %s AND password_hash IS NULL AND NOT legacy_membership_seeded
                """,
                (username,),
            ).rowcount
            if not unseeded:
                return
            db.execute(
                """
                INSERT INTO bank_organization_member (organization_id, username, role) VALUES (%s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (DEFAULT_PROJECT, username, organization_role),
            )
            db.execute(
                """
                INSERT INTO bank_project_member (project_id, organization_id, username, role) VALUES (%s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (DEFAULT_PROJECT, DEFAULT_PROJECT, username, project_role),
            )

    def list_organizations(self, username, super_admin=False):
        with self.store.connect() as db:
            return db.execute(
                """
                SELECT organization.id, organization.name, membership.role FROM bank_organization AS organization
                LEFT JOIN bank_organization_member AS membership
                    ON membership.organization_id = organization.id AND membership.username = %s
                WHERE %s OR membership.role IS NOT NULL
                ORDER BY organization.name, organization.id
                """,
                (username, super_admin),
            ).fetchall()

    def get_organization(self, organization_id, username, super_admin=False):
        with self.store.connect() as db:
            return db.execute(
                """
                SELECT organization.id, organization.name, membership.role FROM bank_organization AS organization
                LEFT JOIN bank_organization_member AS membership
                    ON membership.organization_id = organization.id AND membership.username = %s
                WHERE organization.id = %s AND (%s OR membership.role IS NOT NULL)
                """,
                (username, organization_id, super_admin),
            ).fetchone()

    def list_projects(self, username, super_admin=False):
        with self.store.connect() as db:
            return db.execute(
                PROJECT_ACCESS + " ORDER BY organization.name, project.name, project.id",
                (username, super_admin),
            ).fetchall()

    def get_project(self, project_id, username, super_admin=False):
        with self.store.connect() as db:
            return db.execute(
                PROJECT_ACCESS + " AND project.id = %s", (username, super_admin, project_id),
            ).fetchone()

    def create_organization(self, name, actor):
        with self.store.connect() as db:
            organization_id = _insert_organization(db, name, actor)
        return {"id": organization_id, "name": name, "role": "owner"}

    def register(self, username, display_name, password_hash, spec, timestamp, *, policy_version):
        with self.store.connect() as db:
            _insert_account(db, username, display_name, password_hash, policy_version)
            organization_id = _insert_organization(db, f"Пространство {username}", username)
            project_id = _insert_project(db, organization_id, "Мой проект", username, spec, timestamp)
        return {"organizationId": organization_id, "projectId": project_id}

    def create_project(self, organization_id, name, actor, spec, timestamp, *, super_admin=False):
        with self.store.connect() as db:
            organization = db.execute(
                "SELECT name FROM bank_organization WHERE id = %s FOR UPDATE", (organization_id,),
            ).fetchone()
            if organization is None:
                return None
            membership = db.execute(
                "SELECT role FROM bank_organization_member WHERE organization_id = %s AND username = %s",
                (organization_id, actor),
            ).fetchone()
            if membership is None:
                if not super_admin:
                    return None
                membership = db.execute(
                    "INSERT INTO bank_organization_member (organization_id,username,role) VALUES (%s,%s,'member') RETURNING role",
                    (organization_id, actor),
                ).fetchone()
            project_id = _insert_project(db, organization_id, name, actor, spec, timestamp)
        return {
            "id": project_id, "name": name, "organizationId": organization_id,
            "organizationName": organization["name"], "organizationRole": membership["role"], "role": "manager",
        }

    def list_organization_members(self, organization_id):
        with self.store.connect() as db:
            return db.execute(
                """
                SELECT membership.username, account.display_name AS "displayName", account.avatar, membership.role
                FROM bank_organization_member AS membership
                JOIN bank_account AS account ON account.username = membership.username
                WHERE membership.organization_id = %s ORDER BY account.display_name, membership.username
                """,
                (organization_id,),
            ).fetchall()

    def set_organization_member(self, organization_id, username, role, actor):
        if role is not None:
            _validate_role(role, ORGANIZATION_ROLES)
        with self.store.connect() as db:
            if not _lock_organization(db, organization_id):
                return None
            account = db.execute(
                """
                SELECT account.display_name AS "displayName", membership.role
                FROM bank_account AS account LEFT JOIN bank_organization_member AS membership
                    ON membership.username = account.username AND membership.organization_id = %s
                WHERE account.username = %s
                """,
                (organization_id, username),
            ).fetchone()
            if not account or (role is None and account["role"] is None):
                return None
            if account["role"] == "owner" and role != "owner":
                another_owner = db.execute(
                    """
                    SELECT 1 FROM bank_organization_member
                    WHERE organization_id = %s AND role = 'owner' AND username <> %s LIMIT 1
                    """,
                    (organization_id, username),
                ).fetchone()
                if not another_owner:
                    raise MembershipConflict("У предприятия должен остаться хотя бы один владелец.")
            if role is None:
                db.execute(
                    "DELETE FROM bank_organization_member WHERE organization_id = %s AND username = %s",
                    (organization_id, username),
                )
                _audit(db, organization_id, None, actor, "organization.member.remove", username)
            elif role != account["role"]:
                db.execute(
                    """
                    INSERT INTO bank_organization_member (organization_id, username, role) VALUES (%s, %s, %s)
                    ON CONFLICT (organization_id, username) DO UPDATE SET role = EXCLUDED.role
                    """,
                    (organization_id, username, role),
                )
                _audit(db, organization_id, None, actor, "organization.member.set", username)
            return {"username": username, "displayName": account["displayName"], "role": role}

    def list_project_members(self, project_id):
        with self.store.connect() as db:
            return db.execute(
                """
                SELECT membership.username, account.display_name AS "displayName", account.avatar, membership.role
                FROM bank_project_member AS membership
                JOIN bank_account AS account ON account.username = membership.username
                WHERE membership.project_id = %s ORDER BY account.display_name, membership.username
                """,
                (project_id,),
            ).fetchall()

    def set_project_member(self, project_id, username, role, actor):
        if role is not None:
            _validate_role(role, PROJECT_ROLES)
        with self.store.connect() as db:
            project = db.execute("SELECT organization_id FROM bank_project WHERE id = %s", (project_id,)).fetchone()
            if not project:
                return None
            organization_id = project["organization_id"]
            _lock_organization(db, organization_id)
            account = db.execute(
                """
                SELECT account.display_name AS "displayName", project_member.role
                FROM bank_organization_member AS org_member
                JOIN bank_account AS account ON account.username = org_member.username
                LEFT JOIN bank_project_member AS project_member
                    ON project_member.project_id = %s AND project_member.username = account.username
                WHERE org_member.organization_id = %s AND account.username = %s
                """,
                (project_id, organization_id, username),
            ).fetchone()
            if not account or (role is None and account["role"] is None):
                return None
            if role is None:
                db.execute("DELETE FROM bank_project_member WHERE project_id = %s AND username = %s",
                           (project_id, username))
                _audit(db, organization_id, project_id, actor, "project.member.remove", username)
            elif role != account["role"]:
                db.execute(
                    """
                    INSERT INTO bank_project_member (project_id, organization_id, username, role)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (project_id, username) DO UPDATE SET role = EXCLUDED.role
                    """,
                    (project_id, organization_id, username, role),
                )
                _audit(db, organization_id, project_id, actor, "project.member.set", username)
            return {"username": username, "displayName": account["displayName"], "role": role}

    def create_invite(self, organization_id, actor, organization_role="member", project_id=None, project_role=None,
                      lifetime_hours=72):
        _validate_role(organization_role, ORGANIZATION_ROLES)
        if project_id is None:
            if project_role is not None:
                raise MembershipConflict("Чтобы назначить роль в проекте, укажите проект.")
        else:
            _validate_role(project_role, PROJECT_ROLES)
            if organization_role != "member":
                raise MembershipConflict("Ссылка на проект даёт роль сотрудника на предприятии.")
        token = token_urlsafe(32)
        with self.store.connect() as db:
            if not _lock_organization(db, organization_id):
                return None
            if project_id and db.execute(
                "SELECT 1 FROM bank_project WHERE id = %s AND organization_id = %s", (project_id, organization_id),
            ).fetchone() is None:
                return None
            invitation = db.execute(
                f"""
                INSERT INTO bank_invite AS invite (
                    id, organization_id, project_id, organization_role, project_role, token_digest, created_by, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, clock_timestamp() + %s)
                RETURNING {INVITATION}
                """,
                (uuid4().hex, organization_id, project_id, organization_role, project_role, _invite_digest(token),
                 actor, timedelta(hours=lifetime_hours)),
            ).fetchone()
            _audit(db, organization_id, project_id, actor, "invite.create", invitation["id"])
        return _invite_times(invitation) | {"token": token}

    def list_invites(self, organization_id, project_id=None):
        with self.store.connect() as db:
            rows = db.execute(
                f"""
                SELECT {INVITATION} FROM bank_invite AS invite
                WHERE invite.organization_id = %s AND invite.project_id IS NOT DISTINCT FROM %s AND {PENDING}
                ORDER BY invite.created_at DESC, invite.id DESC
                """,
                (organization_id, project_id),
            ).fetchall()
        return [_invite_times(row) for row in rows]

    def revoke_invite(self, organization_id, invite_id, actor, project_id=None):
        with self.store.connect() as db:
            revoked = db.execute(
                f"""
                UPDATE bank_invite AS invite SET revoked_at = clock_timestamp()
                WHERE invite.organization_id = %s AND invite.id = %s
                    AND invite.project_id IS NOT DISTINCT FROM %s AND {PENDING}
                """,
                (organization_id, invite_id, project_id),
            ).rowcount
            if revoked:
                _audit(db, organization_id, project_id, actor, "invite.revoke", invite_id)
            return bool(revoked)

    def get_invite(self, token):
        with self.store.connect() as db:
            invitation = db.execute(
                f"""
                SELECT organization.name AS "organizationName", project.name AS "projectName",
                    invite.organization_role AS "organizationRole", invite.project_role AS "projectRole",
                    invite.created_at AS "createdAt", invite.expires_at AS "expiresAt"
                FROM bank_invite AS invite
                JOIN bank_organization AS organization ON organization.id = invite.organization_id
                LEFT JOIN bank_project AS project ON project.id = invite.project_id
                WHERE invite.token_digest = %s AND {PENDING}
                """,
                (_invite_digest(token),),
            ).fetchone()
        return _invite_times(invitation)

    def accept_invite(self, token, username, display_name=None, password_hash=None, *, policy_version=None):
        with self.store.connect() as db:
            invitation = db.execute(
                f"""
                SELECT {INVITATION} FROM bank_invite AS invite
                WHERE invite.token_digest = %s AND {PENDING} FOR UPDATE
                """,
                (_invite_digest(token),),
            ).fetchone()
            if not invitation:
                return None
            organization_id, project_id = invitation["organizationId"], invitation["projectId"]
            _lock_organization(db, organization_id)
            if db.execute(
                "SELECT 1 FROM bank_invite WHERE id = %s AND expires_at > clock_timestamp()",
                (invitation["id"],),
            ).fetchone() is None:
                return None
            if password_hash is None:
                account = db.execute(
                    "SELECT username FROM bank_account WHERE username = %s", (username,),
                ).fetchone()
                if not account:
                    raise MembershipConflict("Войдите в существующую учётную запись или создайте новую.")
            else:
                _insert_account(db, username, display_name or username, password_hash, policy_version)
            db.execute(
                """
                INSERT INTO bank_organization_member AS member (organization_id, username, role)
                VALUES (%s, %s, %s)
                ON CONFLICT (organization_id, username) DO UPDATE SET role = EXCLUDED.role
                WHERE array_position(%s, member.role) < array_position(%s, EXCLUDED.role)
                """,
                (organization_id, username, invitation["organizationRole"],
                 list(ORGANIZATION_ROLES), list(ORGANIZATION_ROLES)),
            )
            if project_id:
                db.execute(
                    """
                    INSERT INTO bank_project_member AS member (project_id, organization_id, username, role)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (project_id, username) DO UPDATE SET role = EXCLUDED.role
                    WHERE array_position(%s, member.role) < array_position(%s, EXCLUDED.role)
                    """,
                    (project_id, organization_id, username, invitation["projectRole"],
                     list(PROJECT_ROLES), list(PROJECT_ROLES)),
                )
            db.execute("UPDATE bank_invite SET accepted_by = %s, accepted_at = clock_timestamp() WHERE id = %s",
                       (username, invitation["id"]))
            _audit(db, organization_id, project_id, username, "invite.accept", invitation["id"])
        return _invite_times(invitation)
