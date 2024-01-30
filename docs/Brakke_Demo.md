## Brakke demo

Started at 27-10-2023

## Demo

Write out flow described here

![flow](./23-10-24_UMA-flow-demo.jpg)

This needs to be the end goal of a UMA Solid Demo with following reqs:
* Uses ODRL Rules to dictate Usage Control
* RO can add ODRL Rules to the AS

extra reqs (as can be seen in figure): use LDN inbox for the messages.

### Sequence diagram

```mermaid
sequenceDiagram
    actor RP as Requesting Party
    participant RS as Resource Server
    participant AS as Authorization Server
    actor Owner as Owner

    autonumber
    note over RP, Owner: Assumption: RP knows about resource X, but there is no rule in the AS that grants him access.
    RP->>RS: GET resource X
    RS->>AS: POST resource X <br/> (Fed Authz for UMA §4.1)
    AS-->>RS: return (HTTP 201) ticket <br/> (Fed AuthZ for UMA §4.2)
    RS-->>RP: return (HTTP 401) Unauthorized <br/> Header: ticket + AS Server location <br/> (UMA §3.2.1)
    
    RP->>AS: POST ticket + grant_type + ticket<br/> (UMA §3.3.1)
    AS->>AS: Authorizer checks whether policy exists to grant access*
    AS-->>RP: return (HTTP 400) invalid scope <br/> (UMA §3.3.6)
    
    note over RP, Owner: At this point, the Owner must be made aware of the fact that there was an insuccessfull request to a given resource. <br/>(i) Can be a request from the Owner to the Authorization server to check which RP wanted access to the Resources.<br/>(ii) Can be a notification from the AS to the Owner
	Owner ->>AS: Add UCP to grant access to RP for resource X
    
    RP->>RS: GET resource X
    RS->>AS: POST resource X <br/> (Fed Authz for UMA §4.1)
    AS-->>RS: return (HTTP 201) ticket <br/> (Fed AuthZ for UMA §4.2)
    RS-->>RP: return (HTTP 401) Unauthorized <br/> Header: ticket + AS Server location <br/> (UMA §3.2.1)
    
    RP->>AS: POST ticket + grant_type + ticket<br/> (UMA §3.3.1)
    AS->>AS: Authorizer checks whether policy exists to grant access*
    AS-->>RP: return (HTTP 200) <br/> (UMA §3.3.5)
    
    RP->>RS: GET resource X (with token)
    RS->>RS: Verify token claims**
    RS-->>RP: return (HTTP 200) resource

```

\*: The authorizer here would use an instantiation of interface `UconEnforcementDecision` to `calculateAccessModes` for the given `request` against the stored `Usage Control Rules` (and how those rules should be interpreted -> `N3 Rules`)

\**: The verification of the token can include sending requests to the Authorization Server and other services. Only if they are valid, can the request be granted. 




## TODOs | requirements

* handle prohibition
  * DECISION: future work: Policy management
* send notification to the owner that a request has been asked
  * maybe that should be handled in the Authorizer in the [UMA Authorisation Server](https://github.com/woutslabbinck/uma/packages/uma)
  * DECISION: future work
    * furthermore, this is resolved by adding an ODRL Rule to the rule set
* think about how to handle that a user has to wait for the owner
  * Maybe this is default in the [UMA Authorisation Server](https://github.com/woutslabbinck/uma/packages/uma) when no access modes are returned
  * DECISION: future work
  * current approach: Wait
* Define proper UCP plugin and use proper model for the uma context generated
  * that way proper N3 Rules for koreografeye can be written
* Code cleanups
* (optional) add a store to UcpPatternEnforcement to which other services could add extra ODRL Rules (would allow real use cases where an owner adds an ODRL Rule)
* What about exceptions
  * DECISION: future work 
  * iedereen heeft toegang. BEHALVE ...