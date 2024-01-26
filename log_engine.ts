import { AccessMode } from "@solid/community-server";
import { EyeJsReasoner, readText } from "koreografeye";
import { PolicyExecutor } from "./src/PolicyExecutor";
import { UconRequest, UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { ContainerUCRulesStore as ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";
import { configSolidServer, eqList, createPolicy, purgePolicyStorage, createTemporalPolicy, debug, SimplePolicy } from "./crudUtil";
import { Store } from "n3";
import * as fs from 'fs'
import { UCPLogPlugin } from "./src/plugins/UCPLogPlugin";

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


    // ask read access while read policy present
    const readPolicyRequest = {
        subject: requestingParty,
        action: [aclRead],
        resource: resource,
        owner: owner
    }
    const readPolicy = await createPolicy(uconRulesStorage, { action: odrlRead, owner, resource, requestingParty })
    const readPolicyWhilePresent = await ucpPatternEnforcement.calculateAndExplainAccessModes(readPolicyRequest)
    await purgePolicyStorage(uconRulesContainer);
    console.log("'read' access request while 'read' policy present.")
    console.log("Read access mode should be present:", readPolicyWhilePresent.decision);
    console.log("Explanation:");
    console.log(readPolicyWhilePresent);
    
    
    if (!eqList(readPolicyWhilePresent.decision, [AccessMode.read])) {
        console.log("This policy is wrong.");
        debug(readPolicy, readPolicyRequest, n3Rules.join('\n'))
    }
    console.log();
    // stop server
    await server.stop()


}
main()
