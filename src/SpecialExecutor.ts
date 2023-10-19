import * as N3 from 'n3';
import * as RDF from '@rdfjs/types';
import { Store } from 'n3';
import { Logger, getLogger } from 'log4js';
import { extractGraph, extractPolicies } from 'koreografeye';

export type IPolicyType = {
    node: N3.NamedNode | N3.BlankNode,
    // Policy node
    path: string,        // Input file
    policy: string,      // Policy identifier
    target: string,      // Name of execution target (the idenfier of the policy function)
    order: number,       // Execution order of policy
    args: {               // Name/Value pairs of policy arguments
        [key: string]: RDF.Term[]
    }
};

export abstract class PolicyPlugin {

    constructor() {

    }

    public abstract execute(mainStore: N3.Store, policyStore: N3.Store, policy: IPolicyType): Promise<any>;
}

export type IPolicyExecution = {
    policy: IPolicyType,
    result: any
};

export class SpecialExecutor {

    constructor(private plugins: { [n: string]: PolicyPlugin }) {

    }

    /**
     * Can execute policies that do have some kind of result
     * @param store reasoning result
     * @returns 
     */
    async executePolicies(store: Store): Promise<IPolicyExecution[]> {
        const policies = await extractPolicies(store, "none", {}, getLogger());
        const executions: IPolicyExecution[] = []
        for (const policy of Object.values(policies)) {
            const implementation = this.plugins[policy.target]
            const policyStore = extractGraph(store, policy.node)
            let result
            try {
                // callImplementation, but this time with a result
                result = await implementation.execute(store, policyStore, policy);
            } catch (e) {
                console.log(policy.target, "could not be executed.", e);

            }
            executions.push({ policy, result })
        }
        return executions
    }

}