
import { AccessMode } from "@solid/community-server";
import { EyeJsReasoner, readText } from "koreografeye";
import { PolicyExecutor } from "./src/PolicyExecutor";
import { UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { ContainerUCRulesStore as ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";
import { configSolidServer, eqList, createPolicy, purgePolicyStorage, createTemporalPolicy } from "./crudUtil";

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
    const n3Rules: string[] = [readText('./rules/data-crud-rules.n3')!, readText('./rules/data-crud-temporal.n3')!]
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
    if (!eqList(readNoPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();

    // ask write access without policy present | should fail
    const writeNoPolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    })
    console.log("'write' access request while no policy present.");
    console.log("No access modes should be present:", writeNoPolicy);
    if (!eqList(writeNoPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();

    // ask read access while write policy present
    await createPolicy(uconRulesContainer, { action: odrlWrite, owner, resource, requestingParty })
    const readWhileWritePolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while 'write' policy present.")
    console.log("No access modes should be present:", readWhileWritePolicy);
    if (!eqList(readWhileWritePolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();

    // ask write access while read policy present
    await createPolicy(uconRulesContainer, { action: odrlRead, owner, resource, requestingParty })
    const writeWhileReadPolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'write' access request while 'read' policy present.")
    console.log("No access modes should be present:", writeWhileReadPolicy);
    if (!eqList(writeWhileReadPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();

    // ask read access while temporal policy present (and no others) | should fail
    await createTemporalPolicy(uconRulesContainer, { action: odrlRead, owner, resource, requestingParty }, { from: new Date("2024-01-01"), to: new Date("2024-01-02") })
    const readWhileTemporalReadPolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while temporal 'read' policy present. Out of bound, so no access")
    console.log("No access modes should be present:", readWhileTemporalReadPolicy);
    if (!eqList(readWhileTemporalReadPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();

    // create temporal (from - to) policy (within time)
    await createTemporalPolicy(uconRulesContainer, { action: odrlRead, owner, resource, requestingParty }, { from: new Date(0), to: new Date(new Date().valueOf() + 30_1000) })
    const readWhileTemporalReadPolicyWithin = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while temporal 'read' policy present. Within bound.")
    console.log("Read access mode should be present:", readWhileTemporalReadPolicyWithin);
    if (!eqList(readWhileTemporalReadPolicyWithin, [aclRead])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();

    // TODO: need write policies as well.
    
    // ask read access while read policy present
    await createPolicy(uconRulesContainer, { action: odrlRead, owner, resource, requestingParty })
    const readPolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while 'read' policy present.")
    console.log("Read access mode should be present:", readPolicy);
    if (!eqList(readPolicy, [AccessMode.read])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();


    // ask write access while write policy present
    await createPolicy(uconRulesContainer, { action: odrlWrite, owner, resource, requestingParty })
    const writePolicy = await ucpPatternEnforcement.calculateAccessModes({
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    })
    await purgePolicyStorage(uconRulesContainer);
    console.log("'write' access request while 'write' policy present.")
    console.log("Write access mode should be present:", writePolicy);
    if (!eqList(writePolicy, [AccessMode.write])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();


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
    if (!eqList(usePolicy, [AccessMode.write, AccessMode.read])) {
        amountErrors++
        console.log("This policy is wrong.");
        
    }
    console.log();

    // stop server
    await server.stop()

    if (amountErrors) console.log("Amount of errors:", amountErrors); // only log amount of errors if there are any

}
main()

