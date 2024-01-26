import { Store } from "n3";
import { IPolicyType, PolicyPlugin } from "../PolicyExecutor";
import { AccessMode } from "../UMAinterfaces";
import { Conclusion } from "../UcpPatternEnforcement";
import { accesModesAllowed } from "../util/constants";

export const ucpPluginIdentifier = 'http://example.org/dataUsageLog'

export class UCPLogPlugin extends PolicyPlugin {

    public async execute(mainStore: Store, policyStore: Store, policy: IPolicyType): Promise<Conclusion> {
        const accessModes : AccessMode[] = []
        for (const accessMode of policy.args[accesModesAllowed]) {
            // This is ugly to go back to enum values
            const enumAccesMode = Object.keys(AccessMode)[Object.values(AccessMode).indexOf(accessMode.value as unknown as AccessMode)] as AccessMode
            accessModes.push(enumAccesMode);
            
        }
        
        
        // TODO: think about no permission (explicit)

        return {
            ruleIRI: policy.args['http://example.org/UCrule'][0].value,
            interpretationIRI: policy.args['http://example.org/N3Identifier'][0].value,
            grants: accessModes,
            timestamp: new Date(policy.args['http://purl.org/dc/terms/issued'][0].value),
        }
    }

}    