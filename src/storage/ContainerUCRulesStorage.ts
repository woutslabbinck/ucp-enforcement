import { Store } from "n3";
import { UCRulesStorage } from "./UCRulesStorage";
import { storeToString, turtleStringToStore } from "../util/Conversion";

type RequestInfo = string | Request;
export class ContainerUCRulesStorage implements UCRulesStorage {
    private containerURL: string;
    private fetch: (input: RequestInfo, init?: RequestInit | undefined) => Promise<Response>;
    /**
     * 
     * @param containerURL The URL to an LDP container
     */
    public constructor(containerURL: string, customFetch?: (input: RequestInfo, init?: RequestInit | undefined) => Promise<Response>) {
        this.containerURL = containerURL
        console.log(`[${new Date().toISOString()}] - ContainerUCRulesStore: LDP Container that will be used as source for the Usage Control Rules`, this.containerURL);
        this.fetch = customFetch ?? fetch;
    }

    public async getStore(): Promise<Store> {
        const store = new Store()
        const container = await readLdpRDFResource(this.fetch, this.containerURL);
        const children = container.getObjects(this.containerURL, "http://www.w3.org/ns/ldp#contains", null).map(value => value.value)
        for (const childURL of children) {
            try {
                const childStore = await readLdpRDFResource(this.fetch, childURL);
                store.addQuads(childStore.getQuads(null, null, null, null))
            } catch (e) {
                console.log(`${childURL} is not an RDF resource`);
                
            }

        }
        return store;
    }

    public async addRule(rule: Store): Promise<void> {
        const ruleString = storeToString(rule);
        const response = await this.fetch(this.containerURL,{
            method: "POST",
            headers: { 'content-type': 'text/turtle' },
            body: ruleString
        })
        if (response.status !== 201) {
            console.log(ruleString);  
            throw Error("Above rule could not be added to the store")
        }
    }
    public async getRule(identifier: string): Promise<Store> {
        // would be better if there was a cache <ruleID, ldp:resource>
        const allRules = await this.getStore()
        const rule = extractQuadsRecursive(allRules, identifier);
        return rule
    }
    
    public async deleteRule(identifier: string): Promise<void> {
        // would really benefit from a cache <ruleID, ldp:resource>
        throw Error('not implemented');
    }
}

export async function readLdpRDFResource(fetch:(input: RequestInfo, init?: RequestInit | undefined) => Promise<Response>, resourceURL:string): Promise<Store>{
    const containerResponse = await fetch(resourceURL)

    if (containerResponse.status !== 200) {
        throw new Error(`Resource not found: ${resourceURL}`)
    }
    if (containerResponse.headers.get('content-type') !== 'text/turtle') { // note: should be all kinds of RDF, not only turtle
        throw new Error('Works only on rdf data')
    }
    const text = await containerResponse.text()
    return await turtleStringToStore(text, resourceURL)
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