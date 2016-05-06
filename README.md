# Cryptex [![Build Status](https://travis-ci.org/impl/cryptex.svg?branch=master)](https://travis-ci.org/impl/cryptex) [![Coverage Status](https://coveralls.io/repos/github/impl/cryptex/badge.svg?branch=master)](https://coveralls.io/github/impl/cryptex?branch=master)

Cryptographic APIs and routines for Elixir.

## Supported algorithms

### Cryptographic hashes

* MD4 (`Cryptex.Hasher.MD4`)
* MD5 (`Cryptex.Hasher.MD5`)
* RIPEMD-160 (`Cryptex.Hasher.Ripemd160`)
* SHA-1 (`Cryptex.Hasher.Sha1`)
* SHA-224 (`Cryptex.Hasher.Sha224`)
* SHA-256 (`Cryptex.Hasher.Sha256`)
* SHA-384 (`Cryptex.Hasher.Sha384`)
* SHA-512 (`Cryptex.Hasher.Sha512`)
* Whirlpool (`Cryptex.Hasher.Whirlpool`)

### Message authentication codes

* HMAC (`Cryptex.Mac.Hmac`)

### Key derivation functions

* PBKDF2 (`Cryptex.Kdf.Pbkdf2`)

### Utilities

* Message crypt format encoding (`Cryptex.Mcf`)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add cryptex to your list of dependencies in `mix.exs`:

        def deps do
          [{:cryptex, "~> 0.0.1"}]
        end

  2. Ensure cryptex is started before your application:

        def application do
          [applications: [:cryptex]]
        end

## Examples

### Calculate a SHA-256 hash

```elixir
Cryptex.Hasher.digest(:sha256, "test") |> Base.encode16
  # => "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"

Cryptex.Hasher.digest(Cryptex.Hasher.Algorithm.Sha256, "test") |> Base.encode16

Cryptex.Hasher.new(:sha256)
|> Cryptex.Hasher.new_state
|> Cryptex.Hasher.State.update("te")
|> Cryptex.Hasher.State.update("st")
|> Cryptex.Hasher.State.digest |> Base.encode16

Cryptex.Hasher.digest(:sha256, ["te", "st"]) |> Base.encode16
```

### Calculate the SHA-512 hash of a file

```elixir
Cryptex.Hasher.digest(:sha512, File.stream!("mix.lock")) |> Base.encode16
  # => "BAC0FB5040C777E4125F413A5F0B02D6E8116E9ABDEF331C861F6AF5F7536AFB2B632D3C6FCB379555F32C8DAE735E15C6D1EB2719C0AD6B2526B7073B5D525A"

File.stream!("mix.lock")
|> Enum.into(Cryptex.Hasher.new_state(:sha512))
|> Cryptex.Hasher.State.digest |> Base.encode16
```

### Calculate an HMAC

```elixir
Cryptex.Mac.Hmac.generate(Cryptex.Hasher.new(:sha256), "key", "test") |> Base.encode16
  # => "02AFB56304902C656FCB737CDD03DE6205BB6D401DA2812EFD9B2D36A08AF159"

Cryptex.Mac.Hmac.new(:sha256)
|> Cryptex.Mac.Hmac.generate("key", "test") |> Base.encode16
```

### Verify an HMAC

```
mac = "02AFB56304902C656FCB737CDD03DE6205BB6D401DA2812EFD9B2D36A08AF159"
Cryptex.Mac.Hmac.is_authenticated?(:sha256, "key", "test", mac |> Base.decode16!)
  # => true
```

### Derive a key using PBKDF2 and encode with MCF

```elixir
Cryptex.Kdf.Pbkdf2.derive(Cryptex.Mac.Hmac.new(:sha512), "secret") |> Cryptex.Mcf.encode
  # => "$pbkdf2-sha512$160000$DM31Hc6BkHrbuVi0muAcFQ$cCAm0XJMQ4Go81UiXfO8/9HZHEKWTDTbL37gm9KNA9xeWv1Zi12EmtMx6vxBJD5zECKIx63lVAckGBQIyIKgaA"

Cryptex.Kdf.Pbkdf2.new(Cryptex.Mac.Hmac.new(:sha512))
|> Cryptex.Kdf.Pbkdf2.derive("secret", "DM31Hc6BkHrbuVi0muAcFQ" |> Cryptex.Kdf.Pbkdf2.Mcf.Alphabet.decode!)
|> Cryptex.Mcf.encode
```
