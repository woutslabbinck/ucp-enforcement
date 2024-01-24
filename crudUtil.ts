import { App, AppRunner, AppRunnerInput } from "@solid/community-server";
import * as path from 'path';
import { readLdpRDFResource } from "./src/storage/ContainerUCRulesStorage";
import { UCRulesStorage } from "./src/storage/UCRulesStorage";
import { Store } from "n3";
import { storeToString } from "./src/util/Conversion";

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

export function basicPolicy(baseIri: string, type: { action: string, owner: string, resource: string, requestingParty: string }): string {
    const policy = `@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    @prefix : <${baseIri}> .
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.

    :usagePolicy 
      a odrl:Agreement ;
      odrl:permission :permission.
    
    :permission
      a odrl:Permission ;
      odrl:action <${type.action}> ;
      odrl:target <${type.resource}>;
      odrl:assignee <${type.requestingParty}> ;
      odrl:assigner <${type.owner}> .`
    return policy
}
/**
 * Create an instantiated temporal usage control policy using ODRL and add it to the policy container
 * @param containerURL 
 * @param type 
 * @returns Policy identifier
 */
export async function createTemporalPolicy(containerURL: string, type: { action: string, owner: string, resource: string, requestingParty: string }, window: { from: Date, to: Date }): Promise<string> {
    const policyIRI: string = `http://example.org/${new Date().valueOf()}#`
    let policy = basicPolicy(policyIRI, type)

    // add from constraint (hardcoded, should be made better for production)
    policy += `
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
    <${policyIRI}permission> odrl:constraint [
        odrl:leftOperand odrl:dateTime ;
        odrl:operator odrl:gt ;
        odrl:rightOperand "${window.from.toISOString()}"^^xsd:dateTime ] .
    `
    // add to constraint
    policy += `
    <${policyIRI}permission> odrl:constraint [
        odrl:leftOperand odrl:dateTime ;
        odrl:operator odrl:lt ;
        odrl:rightOperand "${window.to.toISOString()}"^^xsd:dateTime ] .
    `
    await fetch(containerURL, {
        method: "POST",
        headers: { 'content-type': 'text/turtle' },
        body: policy
    })
    return policyIRI
}

/**
 * Create an instantiated usage control policy using ODRL and add it to the policy container
 * @param containerURL 
 * @param type 
 * @returns Policy identifier
 */
export async function createPolicy(containerURL: string, type: { action: string, owner: string, resource: string, requestingParty: string }): Promise<string> {
    const policyIRI: string = `http://example.org/${new Date().valueOf()}#`
    const policy = basicPolicy(policyIRI, type)
    await fetch(containerURL, {
        method: "POST",
        headers: { 'content-type': 'text/turtle' },
        body: policy
    })
    return policyIRI
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
    const ruleIRIs = uconStore.getSubjects('http://www.w3.org/1999/02/22-rdf-syntax-ns#type','http://www.w3.org/ns/odrl/2/Permission', null)
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
export function extractQuadsRecursive(store: Store, subjectIRI: string, existing?:string[]): Store {
    const tempStore = new Store();
    const subjectIRIQuads = store.getQuads(subjectIRI, null, null, null)

    tempStore.addQuads(subjectIRIQuads)
    const existingSubjects = existing ?? [subjectIRI]

    for (const subjectIRIQuad of subjectIRIQuads) {
        if (!existingSubjects.includes(subjectIRIQuad.object.id)){
            tempStore.addQuads(extractQuadsRecursive(store, subjectIRIQuad.object.id, existingSubjects).getQuads(null, null, null, null))
        } 
        else {
            tempStore.addQuad(subjectIRIQuad)
        }
        existingSubjects.push(subjectIRIQuad.object.id)
    }
    return tempStore
}