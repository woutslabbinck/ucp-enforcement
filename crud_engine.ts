import * as fs from 'fs';
import { EyeJsReasoner, readText } from "koreografeye";
import { Store } from "n3";
import { SimplePolicy, UCPPolicy, configSolidServer, purgePolicyStorage, validate } from "./crudUtil";
import { PolicyExecutor } from "./src/PolicyExecutor";
import { AccessMode } from "./src/UMAinterfaces";
import { UconRequest, UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { ContainerUCRulesStore as ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";

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

    // requests
    const readPolicyRequest: UconRequest = {
        subject: requestingParty, action: [aclRead], resource: resource, owner: owner
    }
    const writePolicyRequest: UconRequest = {
        subject: requestingParty, action: [aclWrite], resource: resource, owner: owner
    }
    const usePolicyRequest: UconRequest = {
        subject: requestingParty, action: [aclWrite, aclRead], resource: resource, owner: owner
    }

    // policies 
    const readPolicy: UCPPolicy = { action: odrlRead, owner, resource, requestingParty }
    const writePolicy: UCPPolicy = { action: odrlWrite, owner, resource, requestingParty }
    const temporalReadPolicyOutOfBound: UCPPolicy = {
        action: odrlRead, owner, resource, requestingParty,
        constraints: [
            { operator: "http://www.w3.org/ns/odrl/2/gt", type: "temporal", value: new Date("2024-01-01") }, // from: must be greater than given date
            { operator: "http://www.w3.org/ns/odrl/2/lt", type: "temporal", value: new Date("2024-01-02") }, // to: must be smaller than given date
        ]
    }
    const temporalReadPolicyWithinBound: UCPPolicy = {
        action: odrlRead, owner, resource, requestingParty,
        constraints: [
            { operator: "http://www.w3.org/ns/odrl/2/gt", type: "temporal", value: new Date(0) }, // from: must be greater than given date
            { operator: "http://www.w3.org/ns/odrl/2/lt", type: "temporal", value: new Date(new Date().valueOf() + 30_000) }, // to: must be smaller than given date
        ]
    }
    const temporalWritePolicyOutOfBound: UCPPolicy = {
        action: odrlWrite, owner, resource, requestingParty,
        constraints: [
            { operator: "http://www.w3.org/ns/odrl/2/gt", type: "temporal", value: new Date("2024-01-01") }, // from: must be greater than given date
            { operator: "http://www.w3.org/ns/odrl/2/lt", type: "temporal", value: new Date("2024-01-02") }, // to: must be smaller than given date
        ]
    }
    const temporalWritePolicyWithinBound: UCPPolicy = {
        action: odrlWrite, owner, resource, requestingParty,
        constraints: [
            { operator: "http://www.w3.org/ns/odrl/2/gt", type: "temporal", value: new Date(0) }, // from: must be greater than given date
            { operator: "http://www.w3.org/ns/odrl/2/lt", type: "temporal", value: new Date(new Date().valueOf() + 30_000) }, // to: must be smaller than given date
        ]
    }
    const usePolicy: UCPPolicy = { action: odrlUse, owner, resource, requestingParty }

    let result: boolean

    // ask read access without policy present | should fail
    result = await validate({
        request: readPolicyRequest,
        policies: [],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'read' access request while no policy present.",
    })
    if (!result) amountErrors++;

    // ask write access without policy present | should fail

    result = await validate({
        request: writePolicyRequest,
        policies: [],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'write' access request while no policy present.",
    })
    if (!result) amountErrors++;

    // ask read access while write policy present
    result = await validate({
        request: readPolicyRequest,
        policies: [writePolicy],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'read' access request while 'write' policy present.",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);


    // ask write access while read policy present
    result = await validate({
        request: writePolicyRequest,
        policies: [readPolicy],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'write' access request while 'read' policy present.",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);

    // ask read access while temporal policy present (and no others) | out of bound
    result = await validate({
        request: readPolicyRequest,
        policies: [temporalReadPolicyOutOfBound],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'read' access request while temporal 'read' policy present. Out of bound, so no access",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);

    // ask read access while temporal policy present (and no others) | within bound 
    result = await validate({
        request: readPolicyRequest,
        policies: [temporalReadPolicyWithinBound],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'read' access request while temporal 'read' policy present. Within bound. However, no N3 rule for interpretation.",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);

    // ask write access while temporal policy present (and no others) | out of bound
    result = await validate({
        request: writePolicyRequest,
        policies: [temporalWritePolicyOutOfBound],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'write' access request while temporal 'write' policy present. Out of bound, so no access",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);

    // ask write access while temporal policy present (and no others) | within bound 
    result = await validate({
        request: writePolicyRequest,
        policies: [temporalWritePolicyWithinBound],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'write' access request while temporal 'write' policy present. Within bound. However, no N3 rule for interpretation.",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);

    // ask read access while read policy present
    result = await validate({
        request: readPolicyRequest,
        policies: [readPolicy],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [AccessMode.read],
        descriptionMessage: "'read' access request while 'read' policy present.",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);

    // ask write access while write policy present
    result = await validate({
        request: writePolicyRequest,
        policies: [writePolicy],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [AccessMode.write],
        descriptionMessage: "'write' access request while 'write' policy present.",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);

    // ask read and write access while use policy present
    result = await validate({
        request: usePolicyRequest,
        policies: [usePolicy],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [AccessMode.write, AccessMode.read],
        descriptionMessage: "'read' and 'write' access request while 'use' policy present.",
    })
    if (!result) amountErrors++;
    await purgePolicyStorage(uconRulesContainer);
    // stop server
    await server.stop()

    if (amountErrors) console.log("Amount of errors:", amountErrors); // only log amount of errors if there are any

}
main()

