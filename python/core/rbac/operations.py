# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Any, Iterable, Protocol

from core.rbac.dto import UserCreateDTO, UserUpdateDTO
from core.rbac.errors import EmailTakenError, UsernameTakenError
from core.rbac.rules import (
    check_add_user_to_groups_is_allowed,
    check_all_groups_exists,
    check_password_meet_requirements,
    check_remove_user_from_groups_is_allowed,
    check_users_can_be_blocked,
)
from core.rbac.types import GroupBasicInfo, GroupID, PasswordRequirements, SourceType, UserBasicInfo, UserID
from core.types import ShortObjectInfo


class UserDBProtocol(Protocol):
    def get_users_info(self, ids: Iterable[UserID]) -> Iterable[UserBasicInfo]:
        ...

    def get_user_by_email(self, email: str) -> ShortObjectInfo | None:
        ...

    def get_user_by_username(self, username: str) -> ShortObjectInfo | None:
        ...

    def create_user(self, data: UserCreateDTO) -> UserID:
        ...

    def update_user(self, user_id: UserID, **fields: Any) -> UserID:
        ...

    def set_password(self, user_id: UserID, password: str) -> UserID:
        ...

    def remove_login_attempts_block(self, user_ids: Iterable[UserID]) -> None:
        ...

    def activate_users(self, user_ids: Iterable[UserID]) -> None:
        ...

    def deactivate_users(self, user_ids: Iterable[UserID]) -> None:
        ...


class GroupDBProtocol(Protocol):
    def get_groups_info(self, ids: Iterable[GroupID]) -> Iterable[GroupBasicInfo]:
        ...

    def add_user_to_groups(self, user_id: UserID, groups: Iterable[GroupID]) -> None:
        ...

    def remove_user_from_groups(self, user_id: UserID, groups: Iterable[GroupID]) -> None:
        ...


def create_new_user(
    data: UserCreateDTO, db: UserDBProtocol, password_requirements: PasswordRequirements | None
) -> UserID:
    if db.get_user_by_username(username=data.username) is not None:
        raise UsernameTakenError()

    if data.email and db.get_user_by_email(email=data.email) is not None:
        raise EmailTakenError()

    if password_requirements:
        check_password_meet_requirements(password=data.password, requirements=password_requirements)

    return db.create_user(data=data)


def update_user_information(user_id: UserID, data: UserUpdateDTO, db: UserDBProtocol) -> UserID:
    user_with_email = db.get_user_by_email(email=data.email)
    if data.email and user_with_email is not None and user_with_email.id != user_id:
        raise EmailTakenError()

    return db.update_user(user_id=user_id, **data.dict(exclude_none=True))


def update_user_password(
    user_id: UserID, new_password: str, db: UserDBProtocol, password_requirements: PasswordRequirements
) -> UserID:
    check_password_meet_requirements(password=new_password, requirements=password_requirements)
    return db.set_password(user_id=user_id, password=new_password)


def add_user_to_groups(user_id: UserID, groups: Iterable[GroupID], db: GroupDBProtocol) -> set[GroupID]:
    group_ids = set(groups)

    groups_info = tuple(db.get_groups_info(ids=group_ids))

    check_all_groups_exists(group_candidates=group_ids, existing_groups=groups_info)
    check_add_user_to_groups_is_allowed(groups=groups_info)

    db.add_user_to_groups(user_id=user_id, groups=group_ids)

    return group_ids


def remove_user_from_groups(user_id: UserID, groups: Iterable[GroupID], db: GroupDBProtocol) -> set[GroupID]:
    group_ids = set(groups)

    groups_info = tuple(db.get_groups_info(ids=group_ids))

    check_all_groups_exists(group_candidates=group_ids, existing_groups=groups_info)
    check_remove_user_from_groups_is_allowed(groups=groups_info)

    db.remove_user_from_groups(user_id=user_id, groups=group_ids)

    return group_ids


def block_users(users: Iterable[UserID], db: UserDBProtocol) -> Iterable[UserID]:
    user_ids = tuple(users)
    users_info = tuple(db.get_users_info(ids=user_ids))

    check_users_can_be_blocked(users=users_info)

    db.deactivate_users(user_ids=user_ids)

    return user_ids


def unblock_users(users: Iterable[UserID], db: UserDBProtocol) -> Iterable[UserID]:
    users_info = tuple(db.get_users_info(ids=users))

    all_users = {user.id for user in users_info}
    db.remove_login_attempts_block(user_ids=all_users)

    not_ldap_users = {user.id for user in users_info if user.type != SourceType.LDAP}
    if not_ldap_users:
        db.activate_users(user_ids=not_ldap_users)

    return all_users
