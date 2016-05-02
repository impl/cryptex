# ExCrypto

Elixir cryptographic APIs and routines.

## Supported algorithms

### Cryptographic hashes

* MD4 (`ExCrypto.Hasher.MD4`)
* MD5 (`ExCrypto.Hasher.MD5`)
* RIPEMD-160 (`ExCrypto.Hasher.Ripemd160`)
* SHA-1 (`ExCrypto.Hasher.Sha1`)
* SHA-224 (`ExCrypto.Hasher.Sha224`)
* SHA-256 (`ExCrypto.Hasher.Sha256`)
* SHA-384 (`ExCrypto.Hasher.Sha384`)
* SHA-512 (`ExCrypto.Hasher.Sha512`)
* Whirlpool (`ExCrypto.Hasher.Whirlpool`)

### Message authentication codes

* HMAC (`ExCrypto.Mac.Hmac`)

### Key derivation functions

* PBKDF2 (`ExCrypto.Kdf.Pbkdf2`)

### Utilities

* Message crypt format encoding (`ExCrypto.Mcf`)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add ex_crypto to your list of dependencies in `mix.exs`:

        def deps do
          [{:ex_crypto, "~> 0.0.1"}]
        end

  2. Ensure ex_crypto is started before your application:

        def application do
          [applications: [:ex_crypto]]
        end

## Examples

### Calculate a SHA-256 hash

    ExCrypto.Hasher.digest!(:sha256, "test") |> Base.encode16 # => "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
    ExCrypto.Hasher.digest!(ExCrypto.Hasher.Sha256, "test") |> Base.encode16
    ExCrypto.Hasher.new!(:sha256) |> ExCrypto.Hasher.update!("te") |> ExCrypto.Hasher.update!("st") |> ExCrypto.Hasher.digest! |> Base.encode16

### Calculate an HMAC

    ExCrypto.Mac.Hmac.hmac!(:sha256, "key", "test") |> Base.encode16 # => "02AFB56304902C656FCB737CDD03DE6205BB6D401DA2812EFD9B2D36A08AF159"
    ExCrypto.Mac.Hmac.new!(:sha256) |> ExCrypto.Mac.Hmac.hmac!("key", "test") |> Base.encode16

### Derive a key using PBKDF2 and encode with MCF

    ExCrypto.Kdf.Pbkdf2.new!(ExCrypto.Mac.Hmac.new!(:sha512), "key") |> ExCrypto.Mcf.encode!
      # => "$pbkdf2-sha512$160000$PL6NBXxB1q4xR/NA66khgQ$FU.nYukhtdnPuamHO3nRrRby4irh2Rje6bDyCzRiKBdvuCr5InY1jdNbyUMkYHXZUs5phIp0aVcXyc21drs0ew"
