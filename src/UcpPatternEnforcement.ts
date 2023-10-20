import { Store, DataFactory } from "n3";
import { Reasoner, rdfTransformStore, rdfTransformString } from "koreografeye"
import { SpecialExecutor } from "./SpecialExecutor";
import { Principal, Ticket, AccessMode } from "./UMAinterfaces";
const {quad, namedNode} = DataFactory
/**
 * Actuall class and function I want
 */
export class UcpPatternEnforcement {


    constructor(private odrlPolicies: Store, private odrlRules: string[], private reasoner: Reasoner, private executor: SpecialExecutor) {
        
    }

    async calculateAccessModes(context: { client: Principal; request: Ticket; }): Promise<AccessMode[]> {
        // go from context to a request that contains all context

        const { client, request} = context
        const contextStore = new Store()
        const contextIRI = 'http://example.org/context'
        contextStore.addQuads([
            quad(namedNode(contextIRI), namedNode('http://example.org/resourceOwner'), namedNode(request.owner)),
            quad(namedNode(contextIRI), namedNode('http://example.org/requestingParty'), namedNode(client.webId)),
            quad(namedNode(contextIRI), namedNode('http://example.org/target'), namedNode(request.sub.iri))
        ])
        
        for (const accessMode of Array.from(request.requested)) {            
            contextStore.addQuad(namedNode(contextIRI), namedNode('http://example.org/requestPermission'), namedNode(accessMode))
        }

        const reasoningInputStore = new Store()
        reasoningInputStore.addQuads(this.odrlPolicies.getQuads(null, null, null, null))
        reasoningInputStore.addQuads(contextStore.getQuads(null, null, null, null))

        // TODO: remove in production
        // console.log("input:");
        // console.log(await rdfTransformStore(reasoningInputStore, 'text/turtle'));
        
        // Reason
        const reasoningResult = await this.reasoner.reason(reasoningInputStore, this.odrlRules);

        // TODO: remove in production
        // console.log("reasoning output:");
        // console.log(await rdfTransformStore(reasoningResult, 'text/turtle'));

        // extract and execute policies
        const accessModes : AccessMode[] = []
        const executedPolicies = await this.executor.executePolicies(reasoningResult)
        // if no policies -> ask owner for request -> plugin?
        if (executedPolicies.length === 0) {
            // no access
            // TODO: ask owner access
            // TODO: let user know
            console.log("no policies");
            
        }
        // if policies -> executePolicy: return value accessmodes in an object somehow?
        for (const executedPolicy of executedPolicies) {
            accessModes.push(...executedPolicy.result)
        }
        return accessModes
    }
}