import { EyeJsReasoner, readText } from "koreografeye";
import * as path from 'path';
import { PolicyExecutor } from "./src/PolicyExecutor";
import { AccessMode } from "./src/UMAinterfaces";
import { UconRequest, UcpPatternEnforcement } from "./src/UcpPatternEnforcement";
import { UcpPlugin } from "./src/plugins/UCPPlugin";
import { DirectoryUCRulesStorage } from "./src/storage/DirectoryUCRulesStorage";
import { storeToString } from "./src/util/Conversion";
import { configSolidServer } from "./crudUtil";
import { ContainerUCRulesStorage } from "./src/storage/ContainerUCRulesStorage";

async function main() {
    // load plugin
    const plugins = { "http://example.org/dataUsage": new UcpPlugin() }
    // instantiate koreografeye policy executor
    const policyExecutor = new PolicyExecutor(plugins)

    // load UCON (ODRL) Rules from a directory 
    const uconRulesStorage = new DirectoryUCRulesStorage(path.join(__dirname, "policies"))

    // load N3 Rules from a directory | TODO: utils are needed
    const n3Rules: string[] = [readText('./rules/data-usage-rule.n3')!]

    // instantiate the enforcer using the policy executor,
    const ucpPatternEnforcement = new UcpPatternEnforcement(uconRulesStorage, n3Rules, new EyeJsReasoner([
        "--quiet",
        "--nope",
        "--pass"]), policyExecutor)

    const request: UconRequest = {
        subject: "https://woslabbi.pod.knows.idlab.ugent.be/profile/card#me",
        action: [AccessMode.read],
        resource: "http://localhost:3000/test.ttl",
        owner: "http://localhost:3000/alice/profile/card#me"
    }

    // calculate access modes, which can be used in https://github.com/woutslabbinck/uma
    const accessModes = await ucpPatternEnforcement.calculateAccessModes(
        request)
    console.log(accessModes);

}
main()

async function dynamicStores() {
    // directory policy store
    const directoryRulesStorage = new DirectoryUCRulesStorage(path.join(__dirname, "policies"))

    const directoryStore = await directoryRulesStorage.getStore();
    // console.log(storeToString(store));

    // container policy store
    // constants
    const portNumber = 3123
    const containerURL = `http://localhost:${portNumber}/`
    // start server
    // configured as following command: $ npx @solid/community-server -p 3123 -c config/memory.json     
    const server = await configSolidServer(3123)
    await server.start()
    // set up policy container
    const uconRulesContainer = `${containerURL}ucon/`
    await fetch(uconRulesContainer, {
        method: "PUT"
    }).then(res => console.log("status creating ucon container:", res.status))
    // add ucon policies (currently fetched from `policies` directory)
    await fetch(uconRulesContainer, {
        method: "POST",
        headers: { 'content-type': 'text/turtle' },
        body: storeToString(directoryStore)
    }).then(res => console.log("status adding policies:", res.status))

    // actual container store
    const containerStorage = new ContainerUCRulesStorage(uconRulesContainer)

    const containerStore = await containerStorage.getStore()
    console.log(storeToString(containerStore));

    // stop server
    await server.stop()

}
// dynamicStores()
