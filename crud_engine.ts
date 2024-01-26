import { AccessMode } from "@solid/community-server";
import { EyeJsReasoner, readText } from "koreografeye";
import { PolicyExecutor } from "./src/PolicyExecutor";
import { UconRequest, UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { ContainerUCRulesStore as ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";
import { configSolidServer, eqList, createPolicy, purgePolicyStorage, createTemporalPolicy, debug, SimplePolicy } from "./crudUtil";
import { Store } from "n3";
import * as fs from 'fs'

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

    const emptyPolicy: SimplePolicy = {
        representation: new Store(),
        agreementIRI: "",
        ruleIRI: ""
    }
    
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

    // create debug directory if it doesn't exist yet
    const createDirIfNotExists = (dir: fs.PathLike) =>
        !fs.existsSync(dir) ? fs.mkdirSync(dir) : undefined;

    createDirIfNotExists('debug');

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
     const readNoPolicyRequest = {
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    }
    const readNoPolicy = await ucpPatternEnforcement.calculateAccessModes(readNoPolicyRequest)
    console.log("'read' access request while no policy present.");
    console.log("No access modes should be present:", readNoPolicy);
    if (!eqList(readNoPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(emptyPolicy, readNoPolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask write access without policy present | should fail
    const writeNoPolicyRequest: UconRequest = {
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    }
    const writeNoPolicy = await ucpPatternEnforcement.calculateAccessModes(writeNoPolicyRequest)
    console.log("'write' access request while no policy present.");
    console.log("No access modes should be present:", writeNoPolicy);
    if (!eqList(writeNoPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(emptyPolicy, writeNoPolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask read access while write policy present
    const readWhileWritePolicyRequest = {
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    }
    let writePolicy = await createPolicy(uconRulesStorage, { action: odrlWrite, owner, resource, requestingParty })
    const readWhileWritePolicy = await ucpPatternEnforcement.calculateAccessModes(readWhileWritePolicyRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while 'write' policy present.")
    console.log("No access modes should be present:", readWhileWritePolicy);
    if (!eqList(readWhileWritePolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(writePolicy, readWhileWritePolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask write access while read policy present
    const writeWhileReadPolicyRequest = {
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    }
    let readPolicy = await createPolicy(uconRulesStorage, { action: odrlRead, owner, resource, requestingParty })
    const writeWhileReadPolicy = await ucpPatternEnforcement.calculateAccessModes(writeWhileReadPolicyRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'write' access request while 'read' policy present.")
    console.log("No access modes should be present:", writeWhileReadPolicy);
    if (!eqList(writeWhileReadPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(readPolicy, writeWhileReadPolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask read access while temporal policy present (and no others) | out of bound
    const readWhileTemporalReadPolicyRequest = {
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    }
    const temporalReadPolicyOutOfBound = await createTemporalPolicy(uconRulesStorage, { action: odrlRead, owner, resource, requestingParty }, { from: new Date("2024-01-01"), to: new Date("2024-01-02") })
    const readWhileTemporalReadPolicy = await ucpPatternEnforcement.calculateAccessModes(readWhileTemporalReadPolicyRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while temporal 'read' policy present. Out of bound, so no access")
    console.log("No access modes should be present:", readWhileTemporalReadPolicy);
    if (!eqList(readWhileTemporalReadPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(temporalReadPolicyOutOfBound, readWhileTemporalReadPolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask read access while temporal policy present (and no others) | within bound 
    const readWhileTemporalReadPolicyWithinRequest = {
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    }
    const temporalReadPolicyWithinBound = await createTemporalPolicy(uconRulesStorage, { action: odrlRead, owner, resource, requestingParty }, { from: new Date(0), to: new Date(new Date().valueOf() + 30_000) })
    const readWhileTemporalReadPolicyWithin = await ucpPatternEnforcement.calculateAccessModes(readWhileTemporalReadPolicyWithinRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while temporal 'read' policy present. Within bound. However, no N3 rule for interpretation.")
    console.log("No access modes should be present:", readWhileTemporalReadPolicyWithin);
    if (!eqList(readWhileTemporalReadPolicyWithin, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(temporalReadPolicyWithinBound, readWhileTemporalReadPolicyWithinRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask write access while temporal policy present (and no others) | out of bound
    const writeWhileTemporalReadPolicyRequest = {
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    }
    const temporalWritePolicyOutOfBound = await createTemporalPolicy(uconRulesStorage, { action: odrlWrite, owner, resource, requestingParty }, { from: new Date("2024-01-01"), to: new Date("2024-01-02") })
    const writeWhileTemporalReadPolicy = await ucpPatternEnforcement.calculateAccessModes(writeWhileTemporalReadPolicyRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'write' access request while temporal 'write' policy present. Out of bound, so no access")
    console.log("No access modes should be present:", writeWhileTemporalReadPolicy);
    if (!eqList(writeWhileTemporalReadPolicy, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(temporalWritePolicyOutOfBound, writeWhileTemporalReadPolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask write access while temporal policy present (and no others) | within bound 
    const writeWhileTemporalReadPolicyWithinRequest = {
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    }
    const temporalWritePolicyWithinBound = await createTemporalPolicy(uconRulesStorage, { action: odrlWrite, owner, resource, requestingParty }, { from: new Date(0), to: new Date(new Date().valueOf() + 30_000) })
    const writeWhileTemporalReadPolicyWithin = await ucpPatternEnforcement.calculateAccessModes(writeWhileTemporalReadPolicyWithinRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'write' access request while temporal 'write' policy present. Within bound. However, no N3 rule for interpretation.")
    console.log("No access modes should be present:", writeWhileTemporalReadPolicyWithin);
    if (!eqList(writeWhileTemporalReadPolicyWithin, [])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(temporalWritePolicyWithinBound, writeWhileTemporalReadPolicyWithinRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask read access while read policy present
    const readPolicyRequest = {
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    }
    readPolicy = await createPolicy(uconRulesStorage, { action: odrlRead, owner, resource, requestingParty })
    const readPolicyWhilePresent = await ucpPatternEnforcement.calculateAccessModes(readPolicyRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while 'read' policy present.")
    console.log("Read access mode should be present:", readPolicyWhilePresent);
    if (!eqList(readPolicyWhilePresent, [AccessMode.read])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(readPolicy, readPolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask write access while write policy present
    const writePolicyRequest = {
        subject: requestingParty,
        action: [aclWrite],
        resource: resource,
        owner: owner
    }
    writePolicy = await createPolicy(uconRulesStorage, { action: odrlWrite, owner, resource, requestingParty })
    const writePolicyWhilePresent = await ucpPatternEnforcement.calculateAccessModes(writePolicyRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'write' access request while 'write' policy present.")
    console.log("Write access mode should be present:", writePolicyWhilePresent);
    if (!eqList(writePolicyWhilePresent, [AccessMode.write])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(writePolicy, writePolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // ask read and write access while use policy present
    const usePolicyRequest = {
        subject: requestingParty,
        action: [aclWrite, aclRead],
        resource: resource,
        owner: owner
    }
    const usePolicy = await createPolicy(uconRulesStorage, { action: odrlUse, owner, resource, requestingParty })
    const RWPolicyWhilePresent = await ucpPatternEnforcement.calculateAccessModes(usePolicyRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' and 'write' access request while 'use' policy present.")
    console.log("Both access modes should be present:", RWPolicyWhilePresent);
    if (!eqList(RWPolicyWhilePresent, [AccessMode.write, AccessMode.read])) {
        amountErrors++
        console.log("This policy is wrong.");
        debug(usePolicy, usePolicyRequest, n3Rules.join('\n'))
    }
    console.log();

    // stop server
    await server.stop()

    if (amountErrors) console.log("Amount of errors:", amountErrors); // only log amount of errors if there are any

}
main()

