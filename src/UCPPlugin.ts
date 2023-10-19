import { Store } from "n3";
import { IPolicyType, PolicyPlugin } from "./SpecialExecutor";
import { AccessMode } from "./UMAinterfaces";

export class UcpPlugin extends PolicyPlugin {



    public async execute(mainStore: Store, policyStore: Store, policy: IPolicyType): Promise<AccessMode[]> {
        
        
        // TODO find a way to get the access modes

        return []
    }

}    