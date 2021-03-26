# Contributing

Note that commits to master and / or  main are prevented in the remote. A precommit hook is located in .githooks that will stop commits to the local master / main. The advantage of this precommit hook is that it stops a valid local commit to master / main then causing git pushes to fail which will then require a reset of the local copy.

To activate it run:

```bash
git config --local core.hooksPath .githooks/
```

To confirm that it is set run:

```bash
git config --local --get core.hooksPath
```

## Error trapping

$Error[0].Exception.GetType().FullName
