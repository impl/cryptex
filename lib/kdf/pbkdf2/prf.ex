defprotocol ExCrypto.Kdf.Pbkdf2.Prf do

  def apply(f, secret, salt)
  def digest_size(f)

end

defimpl ExCrypto.Kdf.Pbkdf2.Prf, for: ExCrypto.Mac.Hmac do

  alias ExCrypto.Mac.Hmac

  defdelegate apply(f, secret, salt), to: Hmac, as: :generate
  defdelegate digest_size(f), to: Hmac

end
