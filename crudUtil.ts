import { App, AppRunner, AppRunnerInput } from "@solid/community-server";
import * as fs from 'fs';
import * as Path from 'path';
import { Explanation, serializePremises } from "./src/Explanation";
import { UconRequest } from "./src/Request";
import { AccessMode } from "./src/UMAinterfaces";
import { UconEnforcementDecision } from "./src/UcpPatternEnforcement";
import { UCRulesStorage } from "./src/storage/UCRulesStorage";
import { turtleStringToStore } from "./src/util/Conversion";
import { readLdpRDFResource, SimplePolicy } from "./src/util/Util";

export async function configSolidServer(port: number): Promise<App> {
    const input: AppRunnerInput = {
        config: Path.join(__dirname, "config", "memory.json"),
        variableBindings: {
            'urn:solid-server:default:variable:port': port,
            'urn:solid-server:default:variable:baseUrl': `http://localhost:${port}/`,
            'urn:solid-server:default:variable:loggingLevel': 'warn',
        }
    }
    const cssRunner = await new AppRunner().create(input)
    return cssRunner
}

/**
 * Create a simple policy with an agreement and one rule
 * Note: should and can be made synchronous
 * @param type 
 * @param baseIri 
 * @returns 
 */
export async function basicPolicy(type: UCPPolicy, baseIri?: string): Promise<SimplePolicy> {
    baseIri = baseIri ?? `http://example.org/${new Date().valueOf()}#` // better would be uuid
    const agreement = baseIri + "usagePolicy";
    const rule = baseIri + "permission";
    const policy = `@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.

    <${agreement}>
      a odrl:Agreement ;
      odrl:permission <${rule}>.
    
    <${rule}>
      a odrl:Permission ;
      odrl:action <${type.action}> ;
      odrl:target <${type.resource}>;
      odrl:assignee <${type.requestingParty}> ;
      odrl:assigner <${type.owner}> .`

    const constraints = createConstraints(rule, type.constraints ?? [])

    const policyStore = await turtleStringToStore([policy, constraints].join("\n"))

    return { representation: policyStore, agreementIRI: agreement, ruleIRI: rule }
}

export function createConstraints(ruleIRI: string, constraints: Constraint[]): string {
    let constraintsString = ""
    for (const constraint of constraints) {
        // note: only temporal constraints currently, so the type is not checked
        constraintsString += `@prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
        @prefix odrl: <http://www.w3.org/ns/odrl/2/> .
        <${ruleIRI}> odrl:constraint [
            odrl:leftOperand odrl:dateTime ;
            odrl:operator <${constraint.operator}> ;
            odrl:rightOperand "${(constraint.value as Date).toISOString()}"^^xsd:dateTime ] .
        `
    }
    return constraintsString
}

/**
 * Interface for a Usage Control Policy.
 * Note: a Usage Control policy currently only has one rule.
 */
export interface UCPPolicy {
    action: string,
    owner: string,
    resource: string,
    requestingParty: string,
    constraints?: Constraint[]
}

/**
 * Interface for a Usage Control Policy Constraint
 */
export interface Constraint {
    type: string,
    operator: string,
    value: any
}

/**
 * Create an instantiated usage control policy using ODRL and add it to the policy container
 * @param uconStorage 
 * @param type 
 * @returns 
 */
export async function createPolicy(uconStorage: UCRulesStorage, type: UCPPolicy): Promise<SimplePolicy> {
    const policyIRI: string = `http://example.org/${new Date().valueOf()}#`
    let SimplePolicy = await basicPolicy(type, policyIRI)
    await uconStorage.addRule(SimplePolicy.representation)
    return SimplePolicy
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

/**
 * Really needs a better name.
 * It stores combined request (context) + policies and the rules interpreting those two.
 * Print out the file name
 * Print out instructions for eye to reason over it (assuming eye is locally installed)
 */
export function storeToReason(combined: string): void {
    const fileName = Path.join('debug', `fullRequest-${new Date().valueOf()}.n3`);
    console.log('execute with eye:', `\neye --quiet --nope --pass-only-new ${fileName}`);

    fs.writeFileSync(fileName, combined)
}

/**
 * Util function to debug why a certain test went wrong
 * @param policies 
 * @param request 
 * @param n3Rules 
 */
export function debug(policies: SimplePolicy[], request: UconRequest, n3Rules: string): void {
    const combined = serializePremises(policies, request, n3Rules)
    storeToReason(combined)
}

/**
 * Validates a request to an ucon rules set and its interepretation.
 * Will produce a proper log when the test fails.
 * To do the decision calculation `calculateAccessModes` from {@link UconEnforcementDecision} is used.
 * 
 * Note: Currently does not clean up the ucon rules storage (it only adds).
 * @param input 
 * @returns 
 */
export async function validate(input: {
    request: UconRequest,
    policies: UCPPolicy[],
    ucpExecutor: UconEnforcementDecision,
    storage: UCRulesStorage,
    descriptionMessage?: string,
    validationMessage?: string,
    expectedAccessModes: AccessMode[],
    n3Rules: string[]
}): Promise<boolean> {
    const { request, policies, ucpExecutor, storage, expectedAccessModes } = input;
    // add policies
    const createdPolicies: SimplePolicy[] = [];
    for (const policy of policies) {
        const created = await createPolicy(storage, policy);
        createdPolicies.push(created)
    }
    // ucp decision
    const explanation = await ucpExecutor.calculateAccessModes(request);

    // debug info
    if (input.descriptionMessage) console.log(input.descriptionMessage);
    const validationMessage = input.validationMessage ?? "Access modes present:"
    console.log(validationMessage, explanation, "Access modes that should be present:", expectedAccessModes);

    const successful = eqList(explanation, expectedAccessModes)
    if (!successful) {
        console.log("This policy is wrong.");
        debug(createdPolicies, request, input.n3Rules.join('\n'))
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
export async function validateAndExplain(input: {
    request: UconRequest,
    policies: UCPPolicy[],
    ucpExecutor: UconEnforcementDecision,
    storage: UCRulesStorage,
    descriptionMessage?: string,
    validationMessage?: string,
    expectedAccessModes: AccessMode[],
    n3Rules: string[]
}): Promise<{ successful: boolean, explanation: Explanation }> {
    const { request, policies, ucpExecutor, storage, expectedAccessModes } = input;
    // add policies
    const createdPolicies: SimplePolicy[] = [];
    for (const policy of policies) {
        const created = await createPolicy(storage, policy);
        createdPolicies.push(created)
    }
    // ucp decision
    const explanation = await ucpExecutor.calculateAndExplainAccessModes(request);

    // debug info
    if (input.descriptionMessage) console.log(input.descriptionMessage);
    const validationMessage = input.validationMessage ?? "Access modes present:"
    console.log(validationMessage, explanation.decision, "Access modes that should be present:", expectedAccessModes);

    const successful = eqList(explanation.decision, expectedAccessModes)
    if (!successful) {
        console.log("This policy is wrong.");
        debug(createdPolicies, request, input.n3Rules.join('\n'))
    }
    console.log();
    return { successful, explanation }
}