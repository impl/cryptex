defmodule Cryptex.Hasher do

  alias Cryptex.Hasher
  alias Cryptex.Hasher.State

  @type algorithm :: Cryptex.Hasher.Algorithm.t | atom

  defstruct module: nil, opts: []
  @opaque t :: %Hasher{}

  @spec new(algorithm, Keyword.t) :: t
  def new(module, opts \\ []) do
    resolved_module = resolve_module(module)
    %Hasher{module: resolved_module, opts: opts}
  end

  @spec new_state(t) :: State.t
  def new_state(%Hasher{module: module, opts: opts}) do
    State.new(module, opts)
  end

  @spec new_state(algorithm, Keyword.t) :: State.t
  def new_state(module, opts \\ []) do
    new(module, opts) |> new_state
  end

  @spec digest(t | algorithm, State.digestable) :: binary
  def digest(hasher_or_module, data)
  def digest(%Hasher{module: module, opts: opts}, data) do
    State.new(module, opts) |> State.update(data) |> State.digest
  end
  def digest(module, data) do
    new(module) |> digest(data)
  end

  @spec block_size(t) :: integer
  def block_size(%Hasher{module: module}), do: module.block_size

  @spec digest_size(t) :: integer
  def digest_size(%Hasher{module: module}), do: module.digest_size

  @spec name(t) :: String.t
  def name(%Hasher{module: module}), do: module.name

  defp resolve_module(module) do
    case Atom.to_string(module) do
      "Elixir." <> _ -> module
      reference -> Module.concat(__MODULE__.Algorithm, Macro.camelize(reference))
    end
  end

  defimpl Collectable do

    def into(%Hasher{} = original) do
      {Hasher.new_state(original), fn
        state, {:cont, data} -> State.update(state, data)
        state, :done -> State.digest(state)
        _, :halt -> :ok
      end}
    end

  end

end
