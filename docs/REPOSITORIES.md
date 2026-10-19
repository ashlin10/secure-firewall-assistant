# Repository destinations

Maintain the same reviewed source and version tags in these private repositories:

- Cisco: https://wwwin-github.cisco.com/aleroyds/secure-firewall-assistant
- GitHub: https://github.com/ashlin10/secure-firewall-assistant

Use the Cisco repository as `origin` and the GitHub copy as `github`. Both are
source destinations; private device inventories, native credential entries,
evidence, virtual environments, and dependency caches never belong in either.

```sh
git remote add origin git@wwwin-github.cisco.com:aleroyds/secure-firewall-assistant.git
git remote add github git@github.com:ashlin10/secure-firewall-assistant.git
```

Do not rerun `remote add` when an existing clone already has these remotes.
The GitHub connection must authenticate with an account authorized for ashlin10;
an authenticated enterprise-managed account is not necessarily that account.
Browser sign-in does not automatically configure command-line Git authentication.

If GitHub requires a different SSH key from Cisco, select it in this clone's
private Git configuration (use your own key path):

```sh
git config --local secureFirewall.githubIdentityFile ~/.ssh/id_ed25519_ashlin10
```

The helper applies that identity only to GitHub pushes. This setting and the key
stay outside tracked source and release packages. Unlock an encrypted key through
your local SSH agent; on macOS the helper also supports an existing Keychain
passphrase. Without this setting, normal SSH configuration applies.

After reviewing and committing a change, run:

```sh
python scripts/push_repositories.py
```

The helper checks the intended destinations and a clean `main` branch, then
pushes main to each remote without force. With `--release-tag v0.1.0`, it also
pushes that existing tag. It does not create tags, rewrite history, synchronize
unreviewed pull requests, or delete remote branches. If one push fails, the
successful remote remains updated; fix authentication/conflicts and rerun.

Make changes in one working clone, review/test them, then push the same commit
to both. Before releases, compare `main` and tag object IDs on both hosts. The
provided CI workflow may need host-specific runner configuration on Cisco GitHub;
the public GitHub macOS/Windows runner matrix is not a claim of available Cisco
Enterprise runners.

Downloadable plugin/source ZIPs are generated from reviewed source using
`uv run python scripts/package.py --output dist`. Attach them to private releases
when release publishing is desired. Build artifacts are ignored by Git; the
reproducible packaging script and dependency lock are tracked.
