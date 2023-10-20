import { Store } from "n3";
import { IPolicyType, PolicyPlugin } from "./SpecialExecutor";
import { AccessMode } from "./UMAinterfaces";
import { rdfTransformStore } from "koreografeye";
import { accesModesAllowed } from "./util/constants";

export const ucpPluginIdentifier = 'http://example.org/dataUsage'

export class UcpPlugin extends PolicyPlugin {

    public async execute(mainStore: Store, policyStore: Store, policy: IPolicyType): Promise<AccessMode[]> {
        const accessModes : AccessMode[] = []
        for (const accessMode of policy.args[accesModesAllowed]) {
            // This is ugly to go back to enum values
            const enumAccesMode = Object.keys(AccessMode)[Object.values(AccessMode).indexOf(accessMode.value as unknown as AccessMode)] as AccessMode
            accessModes.push(enumAccesMode);
            
        }
        
        
        // TODO: think about no permission (explicit)

        return accessModes
    }

}    