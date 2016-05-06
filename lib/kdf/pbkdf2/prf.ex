defprotocol Cryptex.Kdf.Pbkdf2.Prf do

  @spec apply(t, any, binary) :: binary
  def apply(f, secret, salt)

  @spec digest_size(t) :: integer
  def digest_size(f)

end

defimpl Cryptex.Kdf.Pbkdf2.Prf, for: Cryptex.Mac.Hmac do

  alias Cryptex.Mac.Hmac

  defdelegate apply(f, secret, salt), to: Hmac, as: :generate
  defdelegate digest_size(f), to: Hmac

end
