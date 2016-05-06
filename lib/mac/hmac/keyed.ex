defmodule Cryptex.Mac.Hmac.Keyed do

  alias Cryptex.Hasher
  alias Cryptex.Mac.Hmac
  alias Cryptex.Mac.Hmac.Keyed

  defstruct hmac: nil, key: nil
  @type t :: %__MODULE__{hmac: Hmac.t, key: binary}

  @spec new(Hmac.t | Hasher.t | Hasher.algorithm, binary) :: t
  def new(%Hmac{} = hmac, key) do
    %Keyed{hmac: hmac, key: key}
  end
  def new(hasher, key) do
    new(Hmac.new(hasher), key)
  end

  @spec generate(t, Hasher.State.digestable) :: binary
  def generate(%Keyed{hmac: hmac, key: key}, data) do
    Hmac.generate(hmac, key, data)
  end

  @spec is_authenticated?(t, Hasher.State.digestable, binary) :: boolean
  def is_authenticated?(%Keyed{hmac: hmac, key: key}, data, test) do
    Hmac.is_authenticated?(hmac, key, data, test)
  end

end
