export enum AdcmUserStatus {
  Active = 'active',
  Blocked = 'blocked',
}

export enum AdcmUserType {
  Local = 'local',
  Ldap = 'ldap',
}

export interface AdcmUserGroup {
  id: number;
  name: string;
  displayName: string;
}

export interface AdcmUser {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  groups: AdcmUserGroup[];
  status: AdcmUserStatus;
  isBuiltIn: boolean;
  isSuperUser: boolean;
  type: string;
  username: string;
  blockingReason: string;
}

export interface AdcmUsersFilter {
  username?: string;
  status?: AdcmUserStatus;
  type?: AdcmUserType;
}

export interface AdcmCreateUserPayload {
  username: string;
  firstName: string;
  lastName: string;
  email: string;
  groups: number[];
  password: string;
  isSuperUser?: boolean;
}

export type UpdateAdcmUserPayload = Omit<AdcmCreateUserPayload, 'username' | 'password'> & {
  password?: string;
};
