defmodule Cryptex.Kdf.Pbkdf2.Result do

  alias Cryptex.Kdf.Pbkdf2.Prf
  alias Cryptex.Kdf.Pbkdf2.Result

  defstruct prf: nil, rounds: nil, salt: nil, digest: nil
  @type t :: %__MODULE__{prf: Prf.t, rounds: integer, salt: binary, digest: binary}

  @spec new(Prf.t, integer, binary, binary) :: t
  def new(prf, rounds, salt, digest) do
    %Result{prf: prf, rounds: rounds, salt: salt, digest: digest}
  end

  @spec prf(t) :: Prf.t
  def prf(%Result{prf: prf}), do: prf

  @spec rounds(t) :: integer
  def rounds(%Result{rounds: rounds}), do: rounds

  @spec salt(t) :: binary
  def salt(%Result{salt: salt}), do: salt

  @spec digest(t) :: binary
  def digest(%Result{digest: digest}), do: digest

end
