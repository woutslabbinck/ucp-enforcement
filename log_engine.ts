import { EyeJsReasoner, readText } from "koreografeye";
import { PolicyExecutor } from "./src/PolicyExecutor";
import { UconEnforcementDecision, UconRequest, UcpPatternEnforcement, createContext } from "./src/UcpPatternEnforcement";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { ContainerUCRulesStore as ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";
import { configSolidServer, eqList, createPolicy, purgePolicyStorage, createTemporalPolicy, debug, SimplePolicy, UCPPolicy } from "./crudUtil";
import { Store } from "n3";
import * as fs from 'fs'
import * as Path from 'path'

import { UCPLogPlugin } from "./src/plugins/UCPLogPlugin";
import { storeToString } from "./src/util/Conversion";
import { UCRulesStorage } from "./src/storage/UCRulesStorage";
import { AccessMode } from "./src/UMAinterfaces";

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
        action: [aclRead, aclWrite],
        resource: resource,
        owner: owner
    }
    const readPolicy: UCPPolicy = { action: odrlUse, owner, resource, requestingParty }
    await validateAndExplain({
        request: readPolicyRequest,
        policies: [readPolicy],
        ucpExecutor: ucpPatternEnforcement,
        storage: uconRulesStorage,
        n3Rules: n3Rules,
        descriptionMessage: "'read' access request while 'read' policy present.",
        validationMessage: "Read access mode should be present:"
    })
    await purgePolicyStorage(uconRulesContainer);

    // stop server
    await server.stop()


}
main()

/**
 * Validates a request to an ucon rules set and its interepretation.
 * Will produce a proper log when the test fails.
 * To do the decision calculation `calculateAccessModes` from {@link UconEnforcementDecision} is used.
 * 
 * Note: Currently does not clean up the ucon rules storage (it only adds).
 * @param input 
 * @returns 
 */
async function validate(input:{
    request: UconRequest,
    policies: UCPPolicy[],
    ucpExecutor: UconEnforcementDecision,
    storage: UCRulesStorage,
    descriptionMessage?: string,
    validationMessage?: string,
    n3Rules: string[]
}): Promise<boolean> {
    const { request, policies, ucpExecutor, storage } = input;
    // add policies
    const createdPolicies: SimplePolicy[] = [];
    for (const policy of policies) {
        const created = await createPolicy(storage, policy);
        createdPolicies.push(created)
    }
    // ucp decision
    const explanation = await ucpExecutor.calculateAccessModes(request);

    const requestedActions: AccessMode[] = request.action.map(value => Object.keys(AccessMode)[Object.values(AccessMode).indexOf(value as unknown as AccessMode)] as AccessMode   // This is ugly to go back to enum values
    )
    // debug info
    if (input.descriptionMessage) console.log(input.descriptionMessage);
    const validationMessage = input.validationMessage ?? "Access modes present:"
    console.log(validationMessage, explanation, "Access modes that should be present:", requestedActions);

    const successful = eqList(explanation, requestedActions)
    if (!successful) {
        console.log("This policy is wrong.");
        // Explanation | Note: commented out
        // console.log("Explanation:");
        // console.log(explanation);

        // TODO: Rewrite debug. Either list of simple policies or N3 store
        let policiesString = ""
        for (const createdPolicy of createdPolicies) {
            policiesString += storeToString(createdPolicy.representation)
        }
        const context = storeToString(createContext(request))
        const fileContent = [policiesString, context, input.n3Rules.join('\n')].join('\n')
        const fileName = Path.join('debug', `fullRequest-${new Date().valueOf()}.n3`);
        console.log('execute with eye:', `\neye --quiet --nope --pass-only-new ${fileName}`);
        fs.writeFileSync(fileName, fileContent)
    }
    console.log();
    return successful
}
/**
 * Validates a request to an ucon rules set and its interepretation.
 * Will produce a proper log when the test fails.
 * To do the decision calculation `calculateAndExplainAccessModes` from {@link UconEnforcementDecision} is used.
 * 
 * Note: Currently does not clean up the ucon rules storage (it only adds).
 * @param input 
 * @returns 
 */
async function validateAndExplain(input: {
    request: UconRequest,
    policies: UCPPolicy[],
    ucpExecutor: UconEnforcementDecision,
    storage: UCRulesStorage,
    descriptionMessage?: string,
    validationMessage?: string,
    n3Rules: string[]
}): Promise<boolean> {
    const { request, policies, ucpExecutor, storage } = input;
    // add policies
    const createdPolicies: SimplePolicy[] = [];
    for (const policy of policies) {
        const created = await createPolicy(storage, policy);
        createdPolicies.push(created)
    }
    // ucp decision
    const explanation = await ucpExecutor.calculateAndExplainAccessModes(request);

    const requestedActions: AccessMode[] = request.action.map(value => Object.keys(AccessMode)[Object.values(AccessMode).indexOf(value as unknown as AccessMode)] as AccessMode   // This is ugly to go back to enum values
    )
    // debug info
    if (input.descriptionMessage) console.log(input.descriptionMessage);
    const validationMessage = input.validationMessage ?? "Access modes present:"
    console.log(validationMessage, explanation.decision, "Access modes that should be present:", requestedActions);

    const successful = eqList(explanation.decision, requestedActions)
    if (!successful) {
        console.log("This policy is wrong.");
        // Explanation | Note: commented out
        // console.log("Explanation:");
        // console.log(explanation);

        // TODO: Rewrite debug. Either list of simple policies or N3 store
        let policiesString = ""
        for (const createdPolicy of createdPolicies) {
            policiesString += storeToString(createdPolicy.representation)
        }
        const context = storeToString(createContext(request))
        const fileContent = [policiesString, context, input.n3Rules.join('\n')].join('\n')
        const fileName = Path.join('debug', `fullRequest-${new Date().valueOf()}.n3`);
        console.log('execute with eye:', `\neye --quiet --nope --pass-only-new ${fileName}`);
        fs.writeFileSync(fileName, fileContent)
    }
    console.log();
    return successful
}