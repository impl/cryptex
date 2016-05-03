defmodule Cryptex.Hasher.State do

  alias Cryptex.Hasher.Algorithm
  alias Cryptex.Hasher.State

  @type digestable :: binary | Stream.t | Enum.t

  defstruct module: nil, context: nil
  @opaque t :: %State{}

  @spec new(Algorithm.t, Keyword.t) :: t
  def new(module, opts \\ []) do
    %State{module: module, context: module.new(opts)}
  end

  @spec update(t, digestable) :: t
  def update(%State{module: module, context: context} = state, data) when is_binary(data) do
    %State{state | context: module.update(context, data)}
  end
  def update(%State{} = state, data), do: Enum.into(data, state)

  @spec digest(t) :: binary
  def digest(%State{module: module, context: context}), do: module.digest(context)

  defimpl Collectable do

    alias Cryptex.Hasher.State

    def into(%State{} = original) do
      {original, fn
        state, {:cont, data} -> State.update(state, data)
        state, :done -> state
        _, :halt -> :ok
      end}
    end

  end

end
