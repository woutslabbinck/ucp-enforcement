import { UconEnforcementDecision, UconRequest } from "./UcpPatternEnforcement";
import { Principal, Ticket } from "./models/AuthorizerInterfaces";
// copy from Wouter https://github.com/SolidLabResearch/user-managed-access/tree/main/packages/uma/src/models at 19/01/2024
export abstract class Authorizer {
    public abstract authorize(ticket: Ticket, client?: Principal): Promise<Ticket>;
}

// end of copy

export class UcpEngineAuthorizer extends Authorizer {
    constructor(protected decisionEngine: UconEnforcementDecision){
        super();
    }

    public async authorize(ticket: Ticket, client?: Principal): Promise<Ticket> {
        const requests: UconRequest[];

        for (const requestedPermission of ticket.requestedPermission) {
            const request : UconRequest= {
                subject: client?.webId ?? "stubbed", // Note: subject sometimes not there, when is that again? Is that if RS sends request? it is still odd to overload the authorizer if you ask me for UMA 3.2 (https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.2); when the RS asks a ticket https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.4.1
                action: requestedPermission.resource_scopes, // i think scope is access mode, right?
                resource: requestedPermission.resource_id,
                owner: "" // TODO: can I still get the owner? is there still an owner of a
            }
        }
        // TODO: continue and think about whether we need an owner

        await this.decisionEngine.calculateAccessModes({})
        return ticket
    }
}