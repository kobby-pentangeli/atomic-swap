# Test fixtures

`mpl_token_metadata.so` is the Metaplex Token Metadata program (`metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s`), dumped from Solana mainnet-beta with `solana program dump`. The harness loads it into LiteSVM so the mint path can exercise the real `create_metadata_accounts_v3` and `create_master_edition_v3` CPIs offline. Refresh it with:

```sh
solana program dump -u m metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s \
    fixtures/mpl_token_metadata.so
```
