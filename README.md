# Fork of lego

This is fork adds the ability to use multiple INWX accounts for DNS-01 validation on one certificate.

For general documentation, see [the upstream documentation](https://go-acme.github.io/lego/).

# How it works
## Step 1
For each account, you'll need a file like this:
```json
{
    "username": "<your INWX username here>",
    "password": "<your INWX password here>",
    "sharedSecret": "<TFA shared secret, optional>"
}
```
Repeat for each account you want to use
## Step 2
To configure which account should be used for which domain, create a file like this:
```json
{
    "domainConfig": {
        "path to account json (see above)": ["list", "of", "domains"]
    }
}
```

## Step 3
Finally, when running lego, set the `INWX_CONFIG` env variable to the file created in Step 2 and set the flag `--dns="inwx-multi"`

Using absolute paths is recommended.
