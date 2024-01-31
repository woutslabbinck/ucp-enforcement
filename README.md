# (Preventive) Usage Control Decision/Enforcement playground

A playground environment to calculate Access Modes based on ODRL Rules, an [UMA Client Request](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.3.1) and Koreografeye (with accompanying N3 Rules and plugin(s)).
This class will be used in the [UMA Authorisation Server](https://github.com/woutslabbinck/uma/packages/uma) that is being developed to work with the [Community Solid Server](https://github.com/CommunitySolidServer/CommunitySolidServer).

The UMA client request contains the following information
* Resource Owner
* Resource (the target resource)
* Requesting Party
* Requested Access Mode (decided by the Resource Server)

In [`main.ts`](./main.ts) is an example of how it works given.

## run

```sh
npx ts-node main.ts
```

## Info

Data usage (policy 1) plugin: `http://example.org/dataUsage`

## How does it work
<!-- TODO: make architecture drawing of the components -->

There are a couple of components:
* Usage Control Rules storage: A storage containing instantiated concrete policies
* N3 Rules storage: A storage containing a set of N3 rules where each such rule matches a concrete type of UCP to the context. 
The result of which are a set of instructions for a **Koreografeye Plugin** .
* A Plugin storage: A storage containing a set Koreografeye Plugins. (note, they are a bit different than the koreografeye policies as they can return `any` instead of just `boolean`)
* An N3 Reasoner
* A Plugin Executor
* A UCP decision component: Which currently uses all of the above to **reason** over which **access modes** (actions) are granted based on a request.

This means that in an Authorization Server, this component could be used as a decision component.
```typescript
const ucpDecide: UconEnforcementDecision = ...
const accessModes = await ucpDecide.calculateAccessModes({
    subject: "https://woslabbi.pod.knows.idlab.ugent.be/profile/card#me",
    action: ["http://www.w3.org/ns/auth/acl#Read"],
    resource: "http://localhost:3000/test.ttl",
    owner: "http://localhost:3000/alice/profile/card#me"
});
console.log(accessModes);
```
```sh
> [ 'read' ]
```

### Example: CRUD policy engine

In [crud_engine.ts](./crud_engine.ts), a `UconEnforcementDecision` component is initialised.
This means that CRUD action requests can be evaluated against a set of ucon rules and an ucon rules interpreter.

The **ucon rule interpretation** is a combination of N3 rules ([data-crud-rules.n3](./rules/data-crud-rules.n3)), a N3 Reasoner ([eye-js](https://github.com/eyereasoner/eye-js)), a plugin executor ([`PolicyExecutor`](./src/PolicyExecutor.ts)) and a plugin ([`UcpPlugin`](src/plugins/UCPPlugin.ts)). These components all work together as described in [Koreografeye](https://github.com/eyereasoner/Koreografeye).

The **set of ucon rules** can be dynamically generated and added through the ucon rules store through the functions `createPolicy` and `createTemporalPolicy` (see [crudUtil.ts](./crudUtil.ts)).

#### Initialisation

```ts
import { EyeJsReasoner, readText } from "koreografeye";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";
import { PolicyExecutor } from "./src/PolicyExecutor";

// load plugin
const plugins = { "http://example.org/dataUsage": new UcpPlugin() }
// instantiate koreografeye policy executor
const policyExecutor = new PolicyExecutor(plugins)
// ucon storage
const uconRulesStorage = new ContainerUCRulesStorage(uconRulesContainer)
// load N3 Rules from a directory | TODO: utils are needed
const n3Rules: string[] = [readText('./rules/data-crud-rules.n3')!]
// instantiate the enforcer using the policy executor,
const ucpPatternEnforcement = new UcpPatternEnforcement(uconRulesStorage, n3Rules, new EyeJsReasoner([
        "--quiet",
        "--nope",
        "--pass"]), policyExecutor)
```



The code in `crud_engine.ts` evaluates 12[ `UconRequest`](./src/request.ts)s using an instance of [`UconEnforcementDecision`](./src/UcpPatternEnforcement.ts) against a variety of ucon rule sets to verify the engine is working as intended.

When an evaluation fails, e.g. through changing the code, an N3 file will be created in the `debug` directory.
This file will include the request (transformed to RDF and serialized to n-triples), the ucon rule(s) and the N3 interpretation rules.
The contents of the file can then be used with the eye reasoner (either local or [online](https://editor.notation3.org/)).

An example of such file is [crud_full](./crud_full.n3), the conclusion of which can be locally tested with following command: 

```sh
eye --quiet --nope --pass-only-new crud_full.n3 
```

With as conclusion:

```ttl
@prefix fno: <https://w3id.org/function/ontology#>.
@prefix : <http://example.org/>.
@prefix acl: <http://www.w3.org/ns/auth/acl#>.

<urn:uuid:b5e1c037-8f35-41f7-a0dc-58ed0efe229e> a fno:Execution.
<urn:uuid:b5e1c037-8f35-41f7-a0dc-58ed0efe229e> fno:executes :dataUsage.
<urn:uuid:b5e1c037-8f35-41f7-a0dc-58ed0efe229e> :accessModesAllowed acl:Write.
```

As an extra, the same evaluation is also tested for a crud engine that also supports temporal policies. The only difference in that engine is that a [second set of N3 interpretation rules](./rules/data-crud-temporal.n3) are added to interpret temporal ucon rules.

### Example: explanation after decision

In [log_engine.ts](./log_engine.ts), a `UconEnforcementDecision` component is initialised. 
Here, `calculateAndExplainAccessModes` is used to not only decide the access modes calculated, but also to add the explanation to why these access modes would be granted.

For this, another plugin ([UCPLogPlugin](./src/plugins/UCPLogPlugin.ts)) and rule interpretation ([log-usage-rule.n3](./rules/log-usage-rule.n3)) is required.

The engine is initialised as follows:

```js
import { EyeJsReasoner, readText } from "koreografeye";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";
import { PolicyExecutor } from "./src/PolicyExecutor";

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
```
When evaluating a UCONRequest, an **Explanation** is retrieved.

```ts
const explanation = await ucpDecide.calculateAndExplainAccessModes({
    subject: "https://woslabbi.pod.knows.idlab.ugent.be/profile/card#me",
    action: ["http://www.w3.org/ns/auth/acl#Read"],
    resource: "http://localhost:3000/test.ttl",
    owner: "http://localhost:3000/alice/profile/card#me"
});
```

An **Explanation** consists of four components:

- **decision**: This is the same as the grants (array of access modes) from `calculateAccessModes`. It is the **result** of the evaluation
- **request**: The input request
- **conclusions**: The conclusions of the reasoner. A conclusion itself consists of four parts: the **Rule Identifier**, the **Interpration N3 Rule Identifier**, the **grants** allowed (the actual conclusion) and the **timestamp** at which the conclusion was generated. A conclusion can be seen as the proof of following function: $interpretation(rule, context, timestamp) -> grants$
- **algorithm**: Which algorithm is used to interpret the set of conclusions
  - Note: only the **union** operator is currently implemented. That is: $\forall c \in C. grant \in c \Rightarrow grant \in D$ </br>
    For all conclusions in **Conclusions**, if a grant is in conclusion, then it is part of the list of grants in **Decision**.

Having the **Explanation** after an evaluation thus allows for logging with provenance/proof of why a certain action was granted at a certain time.

Some utility functions are added such that an explanation can be serialized to RDF:

- `explanationToRdf`: transforms the Javascript object Explanation to an [N3 Store](https://github.com/rdfjs/N3.js?tab=readme-ov-file#storing) containing the explanation information
- `serializeFullExplanation`: Serializes the explanation (which contains the request), ucon policies and N3 interpretation to [Notation3](https://w3c.github.io/N3/spec/).

```ts
import { Store } from "n3";

// use of explanationToRdf
const explanationStore: Store = explanationToRdf(explanation);

// use of serializeFullExplanation
const uconRules = await uconRulesStorage.getStore();
const serialized: string = serializeFullExplanation(explanation, uconRules, n3Rules.join('\n'));

```

