import { UconEnforcementDecision, UconRequest } from "./UcpPatternEnforcement";
import { Principal, Ticket } from "./models/AuthorizerInterfaces";
// copy from Wouter https://github.com/SolidLabResearch/user-managed-access/tree/main/packages/uma/src/models at 19/01/2024
export abstract class Authorizer {
    public abstract authorize(ticket: Ticket, client?: Principal): Promise<Ticket>;
}

// end of copy

export class UcpEngineAuthorizer extends Authorizer {
    constructor(protected decisionEngine: UconEnforcementDecision) {
        super();
    }

    public async authorize(ticket: Ticket, client?: Principal): Promise<Ticket> {
        const requests: UconRequest[] = []

        for (const requestedPermission of ticket.requestedPermission) {
            // convert ticket to uconrequest
            const request: UconRequest = {
                subject: client?.webId ?? "stubbed", // Note: Subject is only present when a client (on behalf of a RP) sends the requests (UMA 3.3.4). When the RS requests a ticket from the AS, no subject is present (https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.4.1) 
                action: requestedPermission.resource_scopes, // scope description: https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.1.1
                resource: requestedPermission.resource_id,
                owner: "" // In current version, owner is not retrievable from a ticket.
            }

            await this.decisionEngine.calculateGrantedAccessModes(request)
        }

        return ticket
    }
}

// @Wouter: How do you see the authorizer
// function(ticket, principal) -> ticket with more state
// function (ticket, principal) -> permission

// with other words: which is the component/interface currently that makes the decision if a RP request is granted?
/**  
 * GENERAL NOTES
 * 1) it might be unwantend to overload the authorizer if you ask me. 
 * Currently happening during (i) UMA 3.2 (https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.2), when the RS asks a ticket (https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.4.1),
 * and (ii) during UMA 3.3.4 (https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#authorization-assessment), when the client is asking a RPT from the AS. 
 * 
 * 2) It might be useful for the owner to be part of the ticket. This way, it can be embedded in the Usage Control Rules.
 * Argument for having an owner in the Authorizer: how can the AS sent notifications to the owner if there is no owner present.
 */


/**
 * RP -> AS: ask for token
 * path: /uma/token | (urn:uma:default:TokenRoute) | class TokenRequestHandler
 * 
 * 
 * return access token containing concrete permissions ({webid, client, permissions[]} signed with private key)
 * 
 * body returned: { access_token : "", type: ""} (as defined by uma)
 * 
 */

/**
 * RS -> AS: ask for ticket
 * path: /uma/ticket | (urn:uma:default:PermissionRegistrationRoute) | class PermissionRegistrationHandler
 * 
 * return ticket with requested grants and necessary grants
 * 
 */

// PAT: protection API access token, used in the Resource Server (when the RS is a client to the AS)