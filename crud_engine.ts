
import { AccessMode, App, AppRunner, AppRunnerInput } from "@solid/community-server";
import { EyeJsReasoner, readText } from "koreografeye";
import * as path from 'path';
import { PolicyExecutor } from "./src/PolicyExecutor";
import { UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { ContainerUCRulesStore as ContainerUCRulesStorage, readLdpRDFResource } from "./src/storage/ContainerUCRulesStorage";

async function configSolidServer(port: number): Promise<App> {
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

async function createPolicy(containerURL: string, type: { action: string, owner: string, resource: string, requestingParty: string }): Promise<string> {
    const policyIRI: string = `http://example.org/${new Date().valueOf()}#`
    const policy = `@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    @prefix : <${policyIRI}> .
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
    await fetch(containerURL, {
        method: "POST",
        headers: { 'content-type': 'text/turtle' },
        body: policy
    })
    return policyIRI
}

async function purgePolicyStorage(containerURL: string): Promise<void> {
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
function eqList(as: any[], bs: any[]): boolean {
    return as.length === bs.length && as.every(a => bs.includes(a))
}

async function main() {
    // constants
    const aclRead = "http://www.w3.org/ns/auth/acl#Read"
    const aclWrite = "http://www.w3.org/ns/auth/acl#Write"
    const odrlRead = "http://www.w3.org/ns/odrl/2/read"
    const odrlWrite = "http://www.w3.org/ns/odrl/2/modify"
    const odrlUse = "http://www.w3.org/ns/odrl/2/use"

    const owner = "https://pod.woutslabbinck.com/profile/card#me"
    const resource = "http://localhost:3000/test.ttl"
    const requestingParty = "https://woslabbi.pod.knows.idlab.ugent.be/profile/card#me"

    const portNumber = 3123
    const containerURL = `http://localhost:${portNumber}/`

    // start server
    // configured as following command: $ npx @solid/community-server -p 3123 -c config/memory.json     
    const server = await configSolidServer(portNumber)
    await server.start()

    // set up policy container
    const uconRulesContainer = `${containerURL}ucon/`
    await fetch(uconRulesContainer, {
        method: "PUT"
    }).then(res => console.log("status creating ucon container:", res.status))
    console.log();


    // load plugin
    const plugins = { "http://example.org/dataUsage": new UcpPlugin() }
    // instantiate koreografeye policy executor
    const policyExecutor = new PolicyExecutor(plugins)
    // ucon storage
    const uconRulesStorage = new ContainerUCRulesStorage(uconRulesContainer)
    // load N3 Rules from a directory | TODO: utils are needed
    const n3Rules: string[] = [readText('./rules/data-crud-rules.n3')!]
    // instantiate the enforcer using the policy executor,
    const ucpPatternEnforcement = new UcpPatternEnforcement(uconRulesStorage, n3Rules, new EyeJsReasoner([
        "--quiet",
        "--nope",
        "--pass"]), policyExecutor)

    let amountErrors = 0;

    // ask read access without policy present | should fail
    const readNoPolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    })
    console.log("'read' access request while no policy present.");
    console.log("No access modes should be present:", readNoPolicy);
    console.log();
    if (!eqList(readNoPolicy, [])) amountErrors++

    // ask write access without policy present | should fail
    const writeNoPolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    })
    console.log("'write' access request while no policy present.");
    console.log("No access modes should be present:", writeNoPolicy);
    console.log();
    if (!eqList(writeNoPolicy, [])) amountErrors++

    // ask read access while write policy present
    await createPolicy(uconRulesContainer, { action: odrlWrite, owner, resource, requestingParty })
    const readWhileWritePolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while 'write' policy present.;")
    console.log("No access modes should be present:", readWhileWritePolicy);
    console.log();
    if (!eqList(readWhileWritePolicy, [])) amountErrors++

    // ask write access while read policy present
    await createPolicy(uconRulesContainer, { action: odrlRead, owner, resource, requestingParty })
    const writeWhileReadPolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'write' access request while 'read' policy present.;")
    console.log("No access modes should be present:", writeWhileReadPolicy);
    console.log();
    if (!eqList(writeWhileReadPolicy, [])) amountErrors++
    // ask read access while temporal policy present (and no others) | should fail
    // TODO: -> but `?SCOPE log:notIncludes { ?permission odrl:constraint ?anything }.` does not work yet

    // ask read access while read policy present
    await createPolicy(uconRulesContainer, { action: odrlRead, owner, resource, requestingParty })
    const readPolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while 'read' policy present.;")
    console.log("Read access mode should be present:", readPolicy);
    console.log();
    if (!eqList(readPolicy, [AccessMode.read])) amountErrors++


    // ask write access while write policy present
    await createPolicy(uconRulesContainer, { action: odrlWrite, owner, resource, requestingParty })
    const writePolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'write' access request while 'write' policy present.;")
    console.log("Write access mode should be present:", writePolicy);
    console.log();
    if (!eqList(writePolicy, [AccessMode.write])) amountErrors++


    // ask read and write access while use policy present
    await createPolicy(uconRulesContainer, { action: odrlUse, owner, resource, requestingParty })
    const usePolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclWrite, aclRead],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' and 'write' access request while 'use' policy present.")
    console.log("Both access modes should be present:", usePolicy);
    console.log();
    if (!eqList(usePolicy, [AccessMode.write, AccessMode.read])) amountErrors++

    // stop server
    await server.stop()

    if (amountErrors) console.log("Amount of errors:", amountErrors); // only log amount of errors if there are any

}
main()

