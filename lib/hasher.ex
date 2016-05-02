defmodule ExCrypto.Hasher do

  alias ExCrypto.Hasher

  @type t :: module

  @callback new(opts :: Keyword.t) :: any

  @callback update(state :: any, data :: binary) :: any

  @callback digest(state :: any) :: binary

  @callback block_size() :: integer
  @callback digest_size() :: integer

  @callback name() :: String.t

  defstruct module: nil, state: nil

  def new(module, opts \\ []) do
    resolved_module = resolve_module(module)
    %Hasher{module: resolved_module, state: resolved_module.new(opts)}
  end

  def update(%Hasher{module: module, state: state} = hasher, data) do
    %Hasher{hasher | state: module.update(state, data)}
  end

  def digest(%Hasher{module: module, state: state}) do
    module.digest(state)
  end

  def digest(module, data) do
    new(module) |> update(data) |> digest
  end

  def block_size(module), do: resolve_module(module).block_size

  def digest_size(module), do: resolve_module(module).digest_size

  def name(module), do: resolve_module(module).name

  defp resolve_module(module) do
    case Atom.to_string(module) do
      "Elixir." <> _ -> module
      reference -> Module.concat(__MODULE__, String.capitalize(reference))
    end
  end

end
