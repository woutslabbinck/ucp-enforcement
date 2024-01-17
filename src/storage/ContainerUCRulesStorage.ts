import { Store } from "n3";
import { UCRulesStore } from "./UCRulesStore";
import { turtleStringToStore } from "../util/Conversion";

type RequestInfo = string | Request;
export class ContainerUCRulesStore implements UCRulesStore {
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
            const childStore = await readLdpRDFResource(this.fetch, childURL);
            store.addQuads(childStore.getQuads(null, null, null, null))
        }
        return store;
    }
}

async function readLdpRDFResource(fetch:(input: RequestInfo, init?: RequestInit | undefined) => Promise<Response>, resourceURL:string): Promise<Store>{
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