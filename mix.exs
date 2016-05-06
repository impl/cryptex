defmodule Cryptex.Mixfile do
  use Mix.Project

  def project do
    [
      app: :cryptex,
      version: "0.0.1",
      elixir: "~> 1.2",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps,
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        'coveralls.html': :test,
        'coveralls.travis': :test,
      ],
      dialyzer: [
        flags: ["-Wunmatched_returns", "-Werror_handling", "-Wrace_conditions"],
      ],
    ]
  end

  def application do
    [
      applications: [:logger]
    ]
  end

  defp deps do
    [
      {:dialyxir, "~> 0.3.3", only: [:dev, :test]},
      {:earmark, "~> 0.2.1", only: [:dev, :test]},
      {:ex_doc, "~> 0.11.5", only: [:dev, :test]},
      {:excoveralls, "~> 0.5.3", only: :test},
    ]
  end
end
