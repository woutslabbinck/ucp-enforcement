// copy from Wouter https://github.com/SolidLabResearch/user-managed-access/tree/main/packages/uma/src/models at 19/01/2024
// reworked to work with typescript
// works for https://github.com/SolidLabResearch/user-managed-access

export interface Permission {
    resource_id: string,
    resource_scopes: string[]
}

export interface Authorization {
    permissions: Permission[]
}

export interface Principal {
    webId: string,
    clientId: string
}

export interface Ticket {
    id: string,
    requestedPermission: Permission[],
    necessaryGrants: []
}

export interface AccessToken extends Principal, Authorization {}
/* export const Ticket = {
    id: string,
    requestedPermissions: array(Permission),
    necessaryGrants: array(any),
};

export const Permission = {
    resource_id: string,
    resource_scopes: array(string),
};

export const Authorization = {
    permissions: array(Permission),
}

export const Principal = {
    webId: string,
    clientId: $(string),
}

export const AccessToken = intersection(Principal, Authorization); // (both principal and authorization) */
// end copy Wouter