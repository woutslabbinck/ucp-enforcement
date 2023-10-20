import { EyeJsReasoner, parseAsN3Store, readText } from "koreografeye";
import { SpecialExecutor } from "./src/SpecialExecutor";
import { UcpPlugin } from "./src/UCPPlugin";
import { UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { AccessMode } from "./src/UMAinterfaces";
import { Store } from "n3";

async function main() {
    const plugins = { "http://example.org/dataUsage": new UcpPlugin() }
    const specialExecutor = new SpecialExecutor(plugins)

    // TODO: proper loading -> also create proper koreografeye function
    const odrlPolicies = await parseAsN3Store('./policies/data-usage-1.ttl') 
    const odrlRules: string[] = [readText('./rules/data-usage-rule.n3')!] 


    const ucpPatternEnforcment = new UcpPatternEnforcement(odrlPolicies, odrlRules, new EyeJsReasoner([
        "--quiet",
        "--nope",
        "--pass"]), specialExecutor)


    const accessModes = await ucpPatternEnforcment.calculateAccessModes(
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
