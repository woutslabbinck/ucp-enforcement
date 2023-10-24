import { Store, DataFactory } from "n3";
import { Reasoner, rdfTransformStore, rdfTransformString } from "koreografeye"
import { PolicyExecutor as IPolicyExecutor } from "./PolicyExecutor";
import { Principal, Ticket, AccessMode } from "./UMAinterfaces";
const { quad, namedNode } = DataFactory

/**
 * Can calculate Access Modes based on an UMA request, ODRL Rules and N3 Rules using the Koreografeye flow.
 * Currently, prohibitions are not taken into account.
 */
export class UcpPatternEnforcement {


    constructor(private odrlPolicies: Store, private koreografeyeOdrlRules: string[], private reasoner: Reasoner, private executor: IPolicyExecutor) {

    }

    /**
     * Calculates the access modes allowed based using Koreografeye
     * The instantiation of the Usage Control Policies are given to this class as an RDF Graph which contain {@link https://www.w3.org/TR/odrl-model/#rule | ODRL Rules}.
     * On these, reasoning is applied with N3 Rules. Those N3 rules have as conclusion a koreografeye Policy.
     * The conclusion of the reasoning results into a graph with 0..n policies, which are then executed by the plugins. This executioner and plugins are given by the {@link IPolicyExecutor}
     *   If there are zero policies in the conclusion, a request will be sent to the Resource Owner. Furthermore, the user is notified that more information is needed. TODO:
     *   Otherwise, {@link AccessMode | Access modes} are obtained from all the Koreografeye Plugin executions.
     * Finally, all the obtained {@link AccessMode | Access modes} are returned
     * 
     * @param context Context about the client and the request, parsed by an UMA Server.
     * @returns 
     */
    async calculateAccessModes(context: { client: Principal; request: Ticket; }): Promise<AccessMode[]> {
        // go from context to an RDF graph that contains all context
        const { client, request } = context

        const owner = request.owner
        const resource = request.sub.iri
        const requestingParty = client.webId
        const requestedAccessModes = Array.from(request.requested)

        const contextStore = createContext({owner, resource, requestingParty, requestedAccessModes})

        const reasoningInputStore = new Store()
        reasoningInputStore.addQuads(this.odrlPolicies.getQuads(null, null, null, null))
        reasoningInputStore.addQuads(contextStore.getQuads(null, null, null, null))

        // TODO: remove in production
        // console.log("input:");
        // console.log(await rdfTransformStore(reasoningInputStore, 'text/turtle'));

        // Reason using ODRL Rules and N3 Rules
        const reasoningResult = await this.reasoner.reason(reasoningInputStore, this.koreografeyeOdrlRules);

        // TODO: remove in production
        // console.log("reasoning output:");
        // console.log(await rdfTransformStore(reasoningResult, 'text/turtle'));

        // Execute policies
        const accessModes: AccessMode[] = []
        const executedPolicies = await this.executor.executePolicies(reasoningResult)
        // if no policies -> ask owner for request -> plugin?
        if (executedPolicies.length === 0) {
            // no access
            // TODO: ask owner access
            // TODO: let user know that there is no access
            console.log("no policies");

        }
        // if policies -> executePolicy: return value accessmodes in an object somehow?
        for (const executedPolicy of executedPolicies) {
            accessModes.push(...executedPolicy.result)
        }
        return accessModes
    }
}

/**
 * Creates an N3 Store based on the context of an UMA Access Request.
 * Currently, the access request also contain ACL access modes.
 * @param context 
 */
function createContext(context: { owner: string, requestingParty: string, resource: string, requestedAccessModes: AccessMode[] }): Store {
    const contextStore = new Store()
    const { owner, requestingParty, requestedAccessModes, resource } = context
    const contextIRI = 'http://example.org/context'
    contextStore.addQuads([
        quad(namedNode(contextIRI), namedNode('http://example.org/resourceOwner'), namedNode(owner)),
        quad(namedNode(contextIRI), namedNode('http://example.org/requestingParty'), namedNode(requestingParty)),
        quad(namedNode(contextIRI), namedNode('http://example.org/target'), namedNode(resource))
    ])

    for (const accessMode of requestedAccessModes) {
        contextStore.addQuad(namedNode(contextIRI), namedNode('http://example.org/requestPermission'), namedNode(accessMode))
    }
    return contextStore
}