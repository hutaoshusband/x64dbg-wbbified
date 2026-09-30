# Formatter

The main formatter integration for this repository is still the bundled Windows tool:

- `AStyleHelper.exe` from https://github.com/mrexodia/AStyleHelper
- `AStyle.dll` from (`astyle-3.6.9\build\vs2022\AStyle Dll 2022.sln`)

These are used by the existing Windows workflows and helper scripts.

For Linux users, there is also a Python port at `.github/format/AStyleHelper.py`.
It uses [`uv` script metadata](https://docs.astral.sh/uv/guides/scripts/#declaring-script-dependencies) and the [`astyle` wheel](https://github.com/Freed-Wu/astyle-wheel).

## Windows usage

```bat
format.bat
```

Or directly:

```bat
.github\format\AStyleHelper.exe Silent
.github\format\AStyleHelper.exe Check
```

## Linux usage

```bash
uv run --script .github/format/AStyleHelper.py
uv run --script .github/format/AStyleHelper.py Silent
uv run --script .github/format/AStyleHelper.py Check
```

Running the script without `Silent` or `Check` formats the tree and prints each file as it is processed, so users get progress output.

The Python script keeps the old `Silent` / `Check` CLI so it can act as a compatible alternative on non-Windows systems. It formats the git repository containing the current working directory (falling back to the current directory if not in git), and skips files matched by git ignore rules via `git check-ignore --no-index`.
