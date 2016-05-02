defmodule ExCrypto.Hasher do

  alias ExCrypto.Hasher

  @type t :: module

  @callback new(opts :: Keyword.t)
    :: {:ok, state :: any} | {:error, Exception.t}

  @callback update(state :: any, data :: binary)
    :: {:ok, new_state :: any} | {:error, Exception.t}

  @callback digest(state :: any)
    :: {:ok, digest :: binary} | {:error, Exception.t}

  @callback block_size() :: integer
  @callback digest_size() :: integer

  @callback name() :: String.t

  defstruct module: nil, state: nil

  def new!(module, opts \\ []) do
    case new(module, opts) do
      {:ok, hasher} -> hasher
      {:error, error} -> raise error
    end
  end

  def new(module, opts \\ []) do
    resolved_module = resolve_module(module)

    case resolved_module.new(opts) do
      {:ok, state} -> {:ok, %Hasher{module: resolved_module, state: state}}
      {:error, _} = e -> e
    end
  end

  def update!(%Hasher{} = hasher, data) do
    case update(hasher, data) do
      {:ok, new_hasher} -> new_hasher
      {:error, error} -> raise error
    end
  end

  def update(%Hasher{module: module, state: state} = hasher, data) do
    case module.update(state, data) do
      {:ok, new_state} -> {:ok, %Hasher{hasher | state: new_state}}
      {:error, _} = e -> e
    end
  end

  def digest!(%Hasher{} = hasher) do
    case digest(hasher) do
      {:ok, result} -> result
      {:error, error} -> raise error
    end
  end

  def digest(%Hasher{module: module, state: state}) do
    module.digest(state)
  end

  def digest!(module, data) do
    new!(module) |> update!(data) |> digest!
  end

  def digest(module, data) do
    case new(module) do
      {:ok, hasher} ->
        case update(hasher, data) do
          {:ok, new_hasher} -> digest(new_hasher)
          {:error, _} = e -> e
        end
      {:error, _} = e -> e
    end
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
