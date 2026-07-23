

<img width="647" height="513" alt="2026-07-23_19-14-52" src="https://github.com/user-attachments/assets/7dfa3f30-ff51-4469-9ade-78491bafd958" />






# Mouse Macro Recorder

A simple, lightweight **Windows** mouse macro recorder written in **Rust**.

Records mouse movement, left / right / middle button presses & releases, and mouse wheel events.  
Supports long recordings (30+ minutes) with accurate timing playback.

## Features

- ▶ **Start Record** – begins capturing all mouse activity globally
- ⏹ **Stop Record** – ends the current recording
- ⏯ **Play Back** – faithfully replays the recorded sequence with original timing
- Live event counter and duration display while recording
- Memory-efficient storage of events (suitable for half-hour+ macros)
- Clean, native GUI built with `egui` / `eframe`

## Requirements

- Windows 10 / 11
- Rust (stable) – install from https://rustup.rs
- Visual Studio Build Tools (for MSVC linker) if not already installed

## Build & Run

```bash
cd mouse_macro_recorder
cargo build --release
```

The executable will be at:

```
target/release/mouse_macro_recorder.exe
```

Or simply:

```bash
cargo run --release
```

**Tip:** For best results when playing back into games or elevated applications, right-click the `.exe` → **Run as administrator**.

## How it works

1. A global low-level mouse hook (via the `rdev` crate) listens for all mouse events system-wide.
2. While recording, every relevant event is stored with a high-resolution relative timestamp (milliseconds since record start).
3. On playback the events are re-injected using the Windows input simulation APIs, sleeping the exact duration between them so timing is preserved.

## Limitations / Notes

- Only **mouse** events are recorded (keyboard is ignored by design).
- Extremely dense mouse movement (hundreds of events per second) will use more memory; 30-minute recordings are typically only a few dozen MB.
- Some applications (especially those running as admin or with anti-cheat) may ignore simulated input unless this tool is also elevated.
- The window itself does not capture its own mouse events while you interact with the buttons (normal behaviour).

## License

MIT / Apache-2.0 – free to use and modify.
