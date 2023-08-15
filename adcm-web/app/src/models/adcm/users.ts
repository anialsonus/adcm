export enum AdcmUserStatus {
  Active = 'active',
  Blocked = 'blocked',
}

export enum AdcmUserType {
  Local = 'local',
  Ldap = 'ldap',
}

interface AdcmUserGroup {
  id: number;
}

export interface AdcmUser {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  groups: AdcmUserGroup[];
  status: AdcmUserStatus;
  isBuiltIn: boolean;
  isSuperuser: boolean;
  type: string;
  username: string;
}

export interface AdcmUsersFilter {
  username?: string;
  status?: AdcmUserStatus;
  type?: string;
}

export interface CreateAdcmUserPayload {
  name: string;
  description: string;
}

export interface UpdateAdcmUserPayload {
  name: string;
}
