import { EyeJsReasoner, parseAsN3Store, readText } from "koreografeye";
import { PolicyExecutor } from "./src/PolicyExecutor";
import { UcpPlugin } from "./src/UCPPlugin";
import { UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { AccessMode } from "./src/UMAinterfaces";
import { Store } from "n3";

async function main() {
    // load plugin
    const plugins = { "http://example.org/dataUsage": new UcpPlugin() }
    // instantiate koreografeye policy executor
    const policyExecutor = new PolicyExecutor(plugins)

    // load ODRL Rules from a directory | TODO: utils are needed
    const odrlRules = await parseAsN3Store('./policies/data-usage-1.ttl') 

    // load N3 Rules from a directory | TODO: utils are needed
    const n3Rules: string[] = [readText('./rules/data-usage-rule.n3')!] 

    // instantiate the enforcer using the policy executor,
    const ucpPatternEnforcement = new UcpPatternEnforcement(odrlRules, n3Rules, new EyeJsReasoner([
        "--quiet",
        "--nope",
        "--pass"]), policyExecutor)

    
    // calculate access modes, which can be used in https://github.com/woutslabbinck/uma
    const accessModes = await ucpPatternEnforcement.calculateAccessModes(
        {
            client: {
                webId: "https://woslabbi.pod.knows.idlab.ugent.be/profile/card#me"
            },
            request: {
                sub: { iri: "http://localhost:3000/test.ttl" },
                owner: "http://localhost:3000/alice/profile/card#me",
                requested: new Set([AccessMode.read])
            }
        })
    console.log(accessModes);

}
main()
