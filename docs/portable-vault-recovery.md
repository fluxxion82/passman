# Portable vault recovery

Passman stores each Android/Desktop profile's password list as JSON wrapped in a standard CMS file. You can decrypt, inspect, edit, sign, and encrypt it with normal command-line tools; Passman is not needed for those operations.

## Before you begin

1. Sign in to the profile normally.
2. Open **Settings → Portable Vault Recovery**.
3. Use **Copy recovery phrase** and save the 24 words somewhere outside Passman. Record the P12, certificate, and vault paths displayed there.
4. Quit Passman before replacing the vault file. Back up the recovery P12, certificate, and vault together.

The recovery phrase is the PKCS#12 password; it is not the login password. The login password only unlocks `keyring.pmk` through Argon2id. A 24-word English BIP39 phrase carries 256 bits of generated entropy plus its checksum and protects the standard recovery P12.

Keep the phrase in an independent password manager, or record it on paper/metal in a physically secure place. Do **not** keep the only copy in this Passman vault: that would not help with offline recovery. Back up the phrase, recovery P12, certificate, and vault independently.

### When the phrase changes

It is stable for a profile. Adding, editing, deleting, importing, or syncing password entries does not change it. Neither does changing the Passman login password.

Profiles created before phrase support display a legacy Base64URL recovery password. To switch one of those profiles, choose **Upgrade to 24-word phrase** in the recovery dialog. This is the only currently available action that changes the recovery secret. It re-protects the same P12 private key and certificate, so it does **not** decrypt, re-encrypt, or otherwise change the CMS vault file. Record the new phrase before relying on it: the old recovery password will no longer open the live P12.

The examples below use `work`; replace it and the paths with the values Settings displayed.

## Read the password JSON

`keytool` can inspect the PKCS#12 key material. It prompts for the 24-word recovery phrase; type or paste the words exactly as shown, separated by single spaces.

```bash
keytool -list -v -storetype PKCS12 \
  -keystore "$PROFILE_DIR/work.recovery.p12"
```

Use OpenSSL to extract the private key into a temporary, owner-only directory, decrypt the CMS envelope, verify its embedded CMS signature, and print the JSON:

```bash
umask 077
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

openssl pkcs12 -in "$PROFILE_DIR/work.recovery.p12" -nocerts -nodes \
  -out "$TMP_DIR/recovery.key.pem"

openssl cms -decrypt -binary -inform DER \
  -in "$VAULT_PATH" \
  -recip "$PROFILE_DIR/work.recovery.crt" \
  -inkey "$TMP_DIR/recovery.key.pem" \
  -out "$TMP_DIR/vault.signed.p7m"

openssl cms -verify -binary -inform DER -noverify \
  -in "$TMP_DIR/vault.signed.p7m" \
  -out "$TMP_DIR/passwords.json"
```

`-noverify` skips chain validation for the profile's self-signed certificate; it does not skip CMS signature verification. Passman additionally requires that the signer matches the profile's recovery certificate.

## Update the JSON

Preserve every entry's `uuid`; it is the stable identity used for future edits and sync. `id` is only a display order and Passman can renumber it. After editing `$TMP_DIR/passwords.json`, create an attached CMS signature and encrypt that signed object. Then decrypt and verify the new file before atomically replacing the live vault.

```bash
openssl cms -sign -binary -nodetach -md sha256 \
  -in "$TMP_DIR/passwords.json" \
  -signer "$PROFILE_DIR/work.recovery.crt" \
  -inkey "$TMP_DIR/recovery.key.pem" \
  -outform DER -out "$TMP_DIR/vault.signed.new.p7m"

openssl cms -encrypt -binary -aes256 \
  -in "$TMP_DIR/vault.signed.new.p7m" \
  -outform DER -out "$TMP_DIR/work.vault.new.p7m" \
  "$PROFILE_DIR/work.recovery.crt"

openssl cms -decrypt -binary -inform DER \
  -in "$TMP_DIR/work.vault.new.p7m" \
  -recip "$PROFILE_DIR/work.recovery.crt" \
  -inkey "$TMP_DIR/recovery.key.pem" \
  -out "$TMP_DIR/verified.signed.p7m"

openssl cms -verify -binary -inform DER -noverify \
  -in "$TMP_DIR/verified.signed.p7m" \
  -out "$TMP_DIR/verified.passwords.json"

cmp "$TMP_DIR/passwords.json" "$TMP_DIR/verified.passwords.json"
mv "$TMP_DIR/work.vault.new.p7m" "$VAULT_PATH"
```

Do not put the recovery phrase on a command line, in shell history, or in an environment variable. The temporary private-key file is necessary because OpenSSL CMS does not consume a P12 directly. The cleanup limits exposure but secure deletion is not guaranteed on modern storage; use encrypted storage.
