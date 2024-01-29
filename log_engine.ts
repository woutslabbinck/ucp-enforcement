import * as fs from 'fs';
import { EyeJsReasoner, readText } from "koreografeye";
import { Store } from "n3";
import { SimplePolicy, UCPPolicy, configSolidServer, createPolicy, debug, eqList, purgePolicyStorage, validateAndExplain } from "./crudUtil";
import { PolicyExecutor } from "./src/PolicyExecutor";
import { Explanation, UconEnforcementDecision, UconRequest, UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { ContainerUCRulesStore as ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";
import { AccessMode } from "./src/UMAinterfaces";
import { UCPLogPlugin } from "./src/plugins/UCPLogPlugin";
import { UCRulesStorage } from "./src/storage/UCRulesStorage";

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
    const plugins = { "http://example.org/dataUsageLog": new UCPLogPlugin() }
    // instantiate koreografeye policy executor
    const policyExecutor = new PolicyExecutor(plugins)
    // ucon storage
    const uconRulesStorage = new ContainerUCRulesStorage(uconRulesContainer)
    // load N3 Rules from a directory | TODO: utils are needed
    const n3Rules: string[] = [readText('./rules/log-usage-rule.n3')!]
    // instantiate the enforcer using the policy executor,
    const ucpPatternEnforcement = new UcpPatternEnforcement(uconRulesStorage, n3Rules, new EyeJsReasoner([
        "--quiet",
        "--nope",
        "--pass"]), policyExecutor)


    // ask read access and write access while read policy present
    const readPolicyRequest: UconRequest = {
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    }
    const readPolicy: UCPPolicy = { action: odrlRead, owner, resource, requestingParty }
    await validateAndExplain({
        request: readPolicyRequest,
        policies: [readPolicy],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [AccessMode.read],
        descriptionMessage: "'read' access request while 'read' policy present.",
    })
    await purgePolicyStorage(uconRulesContainer);
    
    // ask read access while temporal policy present (and no others) | out of bound
    const temporalReadPolicyOutOfBound: UCPPolicy = {
        action: odrlRead, owner, resource, requestingParty,
        constraints: [
            {operator: "http://www.w3.org/ns/odrl/2/gt", type: "temporal", value: new Date("2024-01-01")}, // from: must be greater than given date
            {operator: "http://www.w3.org/ns/odrl/2/lt", type: "temporal", value: new Date("2024-01-02")}, // to: must be smaller than given date
        ]
    }
    await validateAndExplain({
        request: readPolicyRequest,
        policies: [temporalReadPolicyOutOfBound],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        expectedAccessModes: [],
        descriptionMessage: "'read' access request while temporal 'read' policy present. Out of bound, so no access",
    })
    await purgePolicyStorage(uconRulesContainer);

    // stop server
    await server.stop()
}
main()

