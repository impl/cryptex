defmodule ExCrypto.Mixfile do
  use Mix.Project

  def project do
    [
      app: :ex_crypto,
      version: "0.0.1",
      elixir: "~> 1.2",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps,
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        'coveralls.travis': :test,
      ]
    ]
  end

  def application do
    [
      applications: [:logger]
    ]
  end

  defp deps do
    [
      {:excoveralls, "~> 0.5.3", only: :test},
    ]
  end
end
