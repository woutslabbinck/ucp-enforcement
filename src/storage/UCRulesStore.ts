import { Store } from "n3";

export interface UCRulesStore {
    getStore:() => Promise<Store>
}