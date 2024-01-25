import { App, AppRunner, AppRunnerInput } from "@solid/community-server";
import * as path from 'path';
import { readLdpRDFResource } from "./src/storage/ContainerUCRulesStorage";
import { UCRulesStorage } from "./src/storage/UCRulesStorage";
import { Store } from "n3";
import { storeToString, turtleStringToStore } from "./src/util/Conversion";
import { UconRequest, createContext } from "./src/UcpPatternEnforcement";
import * as fs from 'fs'
import * as Path from 'path'
export async function configSolidServer(port: number): Promise<App> {
    const input: AppRunnerInput = {
        config: path.join(__dirname, "config", "memory.json"),
        variableBindings: {
            'urn:solid-server:default:variable:port': port,
            'urn:solid-server:default:variable:baseUrl': `http://localhost:${port}/`,
            'urn:solid-server:default:variable:loggingLevel': 'warn',
        }
    }
    const cssRunner = await new AppRunner().create(input)
    return cssRunner
}

// instantiated policy consisting of one agreement and one rule
export interface SimplePolicy {
    // representation of the ucon rule + agreement
    representation: Store,
    // identifier of the agreement
    agreementIRI: string,
    // identifier of the rule
    ruleIRI: string
}
/**
 * Create a simple policy with an agreement and one rule
 * Note: should and can be made synchronous
 * @param type 
 * @param baseIri 
 * @returns 
 */
export async function basicPolicy(type: { action: string, owner: string, resource: string, requestingParty: string }, baseIri?: string): Promise<SimplePolicy> {
    baseIri = baseIri ?? `http://example.org/${new Date().valueOf()}#` // better would be uuid
    const agreement = baseIri + "usagePolicy";
    const rule = baseIri + "permission";
    const policy = `@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.

    <${agreement}>
      a odrl:Agreement ;
      odrl:permission <${rule}>.
    
    <${rule}>
      a odrl:Permission ;
      odrl:action <${type.action}> ;
      odrl:target <${type.resource}>;
      odrl:assignee <${type.requestingParty}> ;
      odrl:assigner <${type.owner}> .`

    const policyStore = await turtleStringToStore(policy)

    return { representation: policyStore, agreementIRI: agreement, ruleIRI: rule }
}

/**
 * Create an instantiated temporal usage control policy using ODRL and add it to the policy container
 * @param uconStorage 
 * @param type 
 * @returns 
 */
export async function createTemporalPolicy(uconStorage: UCRulesStorage, type: { action: string, owner: string, resource: string, requestingParty: string }, window: { from: Date, to: Date }): Promise<SimplePolicy> {
    const policyIRI: string = `http://example.org/${new Date().valueOf()}#`
    let { representation: policy, ruleIRI, agreementIRI } = await basicPolicy(type, policyIRI)

    // add from constraint 
    const constraint1 = `
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
    @prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    <${ruleIRI}> odrl:constraint [
        odrl:leftOperand odrl:dateTime ;
        odrl:operator odrl:gt ;
        odrl:rightOperand "${window.from.toISOString()}"^^xsd:dateTime ] .`
    // add to constraint
    const constraint2 = `
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
    @prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    <${ruleIRI}> odrl:constraint [
        odrl:leftOperand odrl:dateTime ;
        odrl:operator odrl:lt ;
        odrl:rightOperand "${window.to.toISOString()}"^^xsd:dateTime ] .`

    // combining rule
    const constraintStore = await turtleStringToStore([constraint1, constraint2].join('\n'))
    const ruleStore = new Store()
    ruleStore.addQuads(policy.getQuads(null, null, null, null))
    ruleStore.addQuads(constraintStore.getQuads(null, null, null, null))
    // storing rule
    await uconStorage.addRule(ruleStore)
    return { representation: ruleStore, ruleIRI, agreementIRI }
}

/**
 * Create an instantiated usage control policy using ODRL and add it to the policy container
 * @param uconStorage 
 * @param type 
 * @returns 
 */
export async function createPolicy(uconStorage: UCRulesStorage, type: { action: string, owner: string, resource: string, requestingParty: string }): Promise<SimplePolicy> {
    const policyIRI: string = `http://example.org/${new Date().valueOf()}#`
    let SimplePolicy = await basicPolicy(type, policyIRI)
    await uconStorage.addRule(SimplePolicy.representation)
    return SimplePolicy
}

export async function purgePolicyStorage(containerURL: string): Promise<void> {
    const container = await readLdpRDFResource(fetch, containerURL);
    const children = container.getObjects(containerURL, "http://www.w3.org/ns/ldp#contains", null).map(value => value.value)
    for (const childURL of children) {
        try {
            await fetch(childURL, { method: "DELETE" })
        } catch (e) {
            console.log(`${childURL} could not be deleted`);
        }
    }
}
// util function that checks whether lists contain the same elements
export function eqList(as: any[], bs: any[]): boolean {
    return as.length === bs.length && as.every(a => bs.includes(a))
}

export async function getUconRule(uconBaseIri: string, uconStorage: UCRulesStorage): Promise<Store> {
    const uconStore = await uconStorage.getStore()
    const ruleIRIs = uconStore.getSubjects('http://www.w3.org/1999/02/22-rdf-syntax-ns#type', 'http://www.w3.org/ns/odrl/2/Permission', null)
        .filter(subject => subject.value.includes(uconBaseIri))

    if (ruleIRIs.length === 0) throw Error("No rule found in the storage.")
    if (ruleIRIs.length > 1) throw Error("Did not expect to find multiple rules.")

    return extractQuadsRecursive(uconStore, ruleIRIs[0].value)
}

/**
 * A recursive search algorithm that gives all quads that a subject can reach (working with circles)
 * 
 * @param store 
 * @param subjectIRI 
 * @param existing IRIs that already have done the recursive search (IRIs in there must not be searched for again)
 * @returns 
 */
export function extractQuadsRecursive(store: Store, subjectIRI: string, existing?: string[]): Store {
    const tempStore = new Store();
    const subjectIRIQuads = store.getQuads(subjectIRI, null, null, null)

    tempStore.addQuads(subjectIRIQuads)
    const existingSubjects = existing ?? [subjectIRI]

    for (const subjectIRIQuad of subjectIRIQuads) {
        if (!existingSubjects.includes(subjectIRIQuad.object.id)) {
            tempStore.addQuads(extractQuadsRecursive(store, subjectIRIQuad.object.id, existingSubjects).getQuads(null, null, null, null))
        }
        else {
            tempStore.addQuad(subjectIRIQuad)
        }
        existingSubjects.push(subjectIRIQuad.object.id)
    }
    return tempStore
}

/**
 * Combine the policy with the request and the N3 rules interpreting the request into a single string
 * @param policy 
 * @param request 
 * @param rules 
 */
export function combine(policy: SimplePolicy, request: UconRequest, n3Rules: string): string{
    // get Policy
    const policyString = storeToString(policy.representation)
    // create context request
    const context = storeToString(createContext(request))
    // create file with N3 rules, context and policy
    const fileContent = [policyString, context, n3Rules].join('\n')
    return fileContent
}

/**
 * Really needs a better name.
 * It stores combined request (context) + policy and the rules interpreting those two.
 * Print out the file name
 * Print out instructions for eye to reason over it (assuming eye is locally installed)
 */
export function storeToReason(combined: string): void {
    const fileName = Path.join('debug',`fullRequest-${new Date().valueOf()}.n3`);
    console.log('execute with eye:', `\neye --quiet --nope --pass-only-new ${fileName}`);
    
    fs.writeFileSync(fileName, combined)
}

/**
 * Util function to debug why a certain test went wrong
 * @param policy 
 * @param request 
 * @param n3Rules 
 */
export function debug(policy: SimplePolicy, request: UconRequest, n3Rules: string): void {
    const combined = combine(policy, request, n3Rules)
    storeToReason(combined)
}