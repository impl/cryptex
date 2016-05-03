defmodule ExCrypto.Hasher.Algorithm do

  @type t :: module

  @callback new(opts :: Keyword.t) :: any

  @callback update(context :: any, data :: binary) :: any

  @callback digest(context :: any) :: binary

  @callback block_size() :: integer
  @callback digest_size() :: integer

  @callback name() :: String.t

end
