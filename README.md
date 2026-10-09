## x64dbg WBB-ified

is a fork of x64dbg: https://github.com/x64dbg/x64dbg

## What can it do?

Essentially x64dbg WBB-ified provides these two updates:

- Additional Anti-Detection against Anti-Debug measures.
- Native in-built and oneclick MCP Server for AI-Agents. Objectively **the most** agentic MCP containing tools for each action a user would be able to interact in the GUI.

## Agentic use (works today)

```powershell
python tools/mcp_stdio_bridge.py --self-test
python tools/mcp_stdio_bridge.py --smoke-test --arch x64
python tools/mcp_stdio_bridge.py --print-config cursor
```

The stdio bridge owns an isolated x64 debugger and exposes 80 MCP tools
(`LoadBinary`, `Disassemble`, `SetBreakpoint`, ...) plus bridge helpers
(`BridgeInfo`, event journal, `.RVA` addresses) to Claude, Cursor, VS Code
and any MCP client. Setup, workflows and the checkpoint roadmap:
[docs/agentic-use.md](docs/agentic-use.md). Verbatim tool reference:
[docs/legacy-tool-catalog.md](docs/legacy-tool-catalog.md).

## Contributing

If you want to contribute in the project you can open a Pull Request explaining:
- What does your contribution improve?
- How can you prove the code you wrote?
- Write clean and readable code with real tests.
- We are **not** against AI, use it if you want, but do not contribute unmaintainable **slop** or **untested** code.

## Join us

- FireflyProtector Advanced Anti-Reverse Engineering Systems: [FireflyProtector.xyz](https://fireflyprotector.xyz/)
- WallbangBros modding/reversing Community: [WallbangBros](https://wallbangbros.com/)
- WallbangBros Discord Server: [Discord](https://discord.com/invite/dUCNKkS2Ve)
