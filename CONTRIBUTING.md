# Contributing

Thanks for your interest! This project began as an MSc dissertation and is now open for collaboration.

## Ways to help
- **Pick a roadmap item** from the README. Items under "Good first issues" are small and self-contained.
- **Report a bug or false positive:** open an issue with the endpoint, the traffic pattern and the layer scores shown on the dashboard.
- **Propose an idea:** open an issue first, so we can agree the approach before you write code.

## Development setup
1. Install the .NET 10 SDK and Python 3.8+ (`pip install requests`).
2. `cd src/ApiSecurityDemo && dotnet run`, then open http://localhost:5000/dashboard
3. Warm up the baselines with `tests/attack-simulations/01_normal_traffic.py` and approve them on the dashboard.
4. Run `python run_all_tests.py` from `tests/attack-simulations/` to check detection before and after your change.

## Pull requests
- Keep each PR focused on one change, and explain *why* in the description.
- If you change scoring or thresholds, include before/after results from the attack simulations.
- Keep decisions explainable: no opaque models. Every score should be traceable to a formula or rule a developer can read.

## Security issues
Please don't open a public issue for a vulnerability in the framework itself. Contact the maintainer through GitHub first.

By contributing, you agree that your contributions are licensed under the MIT License.
