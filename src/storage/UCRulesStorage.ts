import { Store } from "n3";

export interface UCRulesStorage {
    getStore:() => Promise<Store>
}