# Ucp pattern

Fix TODOs, make some actual reasoning that results into acces mode with
a working plugin.
Where that output results into access modes?

create a list of tuples of (odrl rule id, context:Quad[], set<AccessModes>) as output and print it (after #l49: executepolicies)

## run

```sh
npx ts-node main.ts
```

## Info

Data usage (policy 1) plugin: `http://example.org/dataUsage`