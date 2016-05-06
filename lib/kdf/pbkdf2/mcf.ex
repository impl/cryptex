defmodule Cryptex.Kdf.Pbkdf2.Mcf do

  defmodule Alphabet do

    use Cryptex.Utils.Base64, alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./', padding: false

  end

end

defimpl Cryptex.Mcf.Encoder, for: Cryptex.Kdf.Pbkdf2.Result do

  alias Cryptex.Hasher
  alias Cryptex.Kdf.Pbkdf2.Mcf
  alias Cryptex.Kdf.Pbkdf2.Result
  alias Cryptex.Mac.Hmac

  def encode(%Result{prf: %Hmac{} = prf, rounds: rounds, salt: salt, digest: digest}) do
    {"pbkdf2-#{Hmac.hasher(prf) |> Hasher.name}", "#{rounds}$#{Mcf.Alphabet.encode(salt)}$#{Mcf.Alphabet.encode(digest)}"}
  end
  def encode(_) do
    raise ArgumentError, "No representation for this pseudo-random function is available for PBKDF2"
  end

end
