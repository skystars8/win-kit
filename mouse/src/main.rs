#![windows_subsystem = "windows"]

use eframe::egui;
use rdev::{listen, simulate, Button, Event, EventType, Key};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

/// A recorded mouse event with relative timestamp (ms since recording start)
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RecordedEvent {
    /// Milliseconds since the start of recording
    timestamp_ms: u64,
    event: SerializableEventType,
}

/// Serializable version of rdev EventType (only mouse-related)
#[derive(Clone, Debug, Serialize, Deserialize)]
enum SerializableEventType {
    MouseMove { x: f64, y: f64 },
    ButtonPress(ButtonKind),
    ButtonRelease(ButtonKind),
    Wheel { delta_x: i64, delta_y: i64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ButtonKind {
    Left,
    Right,
    Middle,
}

impl From<Button> for ButtonKind {
    fn from(b: Button) -> Self {
        match b {
            Button::Left => ButtonKind::Left,
            Button::Right => ButtonKind::Right,
            Button::Middle => ButtonKind::Middle,
            _ => ButtonKind::Left, // fallback for Unknown etc.
        }
    }
}

impl From<ButtonKind> for Button {
    fn from(b: ButtonKind) -> Self {
        match b {
            ButtonKind::Left => Button::Left,
            ButtonKind::Right => Button::Right,
            ButtonKind::Middle => Button::Middle,
        }
    }
}

struct MacroApp {
    is_recording: Arc<AtomicBool>,
    is_playing: Arc<AtomicBool>,
    is_paused: Arc<AtomicBool>,
    recorded_events: Arc<Mutex<Vec<RecordedEvent>>>,
    record_start: Arc<Mutex<Option<Instant>>>,
    status: String,
    event_count: usize,
    duration_secs: f64,
}

impl MacroApp {
    fn new() -> Self {
        let is_recording = Arc::new(AtomicBool::new(false));
        let is_playing = Arc::new(AtomicBool::new(false));
        let is_paused = Arc::new(AtomicBool::new(false));
        let recorded_events = Arc::new(Mutex::new(Vec::new()));
        let record_start = Arc::new(Mutex::new(None));

        // Start the global mouse + keyboard listener thread once at startup
        {
            let is_recording = Arc::clone(&is_recording);
            let is_playing = Arc::clone(&is_playing);
            let is_paused = Arc::clone(&is_paused);
            let recorded_events = Arc::clone(&recorded_events);
            let record_start = Arc::clone(&record_start);

            thread::spawn(move || {
                let callback = move |event: Event| {
                    // Global hotkeys for pause / unpause (work even when the window is not focused)
                    if let EventType::KeyPress(key) = event.event_type {
                        match key {
                            Key::F1 => {
                                if is_playing.load(Ordering::SeqCst) {
                                    is_paused.store(true, Ordering::SeqCst);
                                }
                            }
                            Key::F2 => {
                                if is_playing.load(Ordering::SeqCst) {
                                    is_paused.store(false, Ordering::SeqCst);
                                }
                            }
                            _ => {}
                        }
                    }

                    // Only record mouse events while recording is active
                    if !is_recording.load(Ordering::SeqCst) {
                        return;
                    }

                    let start: Instant = {
                        let guard = record_start.lock().unwrap();
                        match *guard {
                            Some(s) => s,
                            None => return,
                        }
                    };

                    let elapsed = start.elapsed().as_millis() as u64;

                    let serializable = match event.event_type {
                        EventType::MouseMove { x, y } => {
                            Some(SerializableEventType::MouseMove { x, y })
                        }
                        EventType::ButtonPress(btn) => {
                            Some(SerializableEventType::ButtonPress(btn.into()))
                        }
                        EventType::ButtonRelease(btn) => {
                            Some(SerializableEventType::ButtonRelease(btn.into()))
                        }
                        EventType::Wheel { delta_x, delta_y } => {
                            Some(SerializableEventType::Wheel { delta_x, delta_y })
                        }
                        _ => None, // ignore keyboard and other events for recording
                    };

                    if let Some(sev) = serializable {
                        if let Ok(mut events) = recorded_events.lock() {
                            events.push(RecordedEvent {
                                timestamp_ms: elapsed,
                                event: sev,
                            });
                        }
                    }
                };

                if let Err(e) = listen(callback) {
                    eprintln!("Failed to start global listener: {:?}", e);
                }
            });
        }

        Self {
            is_recording,
            is_playing,
            is_paused,
            recorded_events,
            record_start,
            status: "Ready. Click ▶ Start Record to begin.".to_string(),
            event_count: 0,
            duration_secs: 0.0,
        }
    }

    fn start_recording(&mut self) {
        if self.is_playing.load(Ordering::SeqCst) {
            self.status = "Cannot record while playing.".to_string();
            return;
        }
        // Clear previous recording
        if let Ok(mut events) = self.recorded_events.lock() {
            events.clear();
        }
        *self.record_start.lock().unwrap() = Some(Instant::now());
        self.is_recording.store(true, Ordering::SeqCst);
        self.is_paused.store(false, Ordering::SeqCst);
        self.status = "🔴 Recording... Move mouse & click!".to_string();
        self.event_count = 0;
        self.duration_secs = 0.0;
    }

    fn stop_recording(&mut self) {
        self.is_recording.store(false, Ordering::SeqCst);
        if let Ok(events) = self.recorded_events.lock() {
            self.event_count = events.len();
            if let Some(last) = events.last() {
                self.duration_secs = last.timestamp_ms as f64 / 1000.0;
            } else {
                self.duration_secs = 0.0;
            }
        }
        self.status = format!(
            "✅ Stopped. {} events • {:.1}s",
            self.event_count, self.duration_secs
        );
    }

    fn play_back(&mut self) {
        if self.is_recording.load(Ordering::SeqCst) {
            self.status = "Stop recording first.".to_string();
            return;
        }
        if self.is_playing.load(Ordering::SeqCst) {
            self.status = "Already playing.".to_string();
            return;
        }

        let events = match self.recorded_events.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                self.status = "Error accessing recording.".to_string();
                return;
            }
        };

        if events.is_empty() {
            self.status = "No recording to play.".to_string();
            return;
        }

        self.is_playing.store(true, Ordering::SeqCst);
        self.is_paused.store(false, Ordering::SeqCst);
        self.status = "▶️ Playing back... (F1 pause / F2 resume)".to_string();

        let is_playing = Arc::clone(&self.is_playing);
        let is_paused = Arc::clone(&self.is_paused);

        thread::spawn(move || {
            let mut last_ts: u64 = 0;

            for rec in events {
                // Calculate delay from previous event
                let delay_ms = rec.timestamp_ms.saturating_sub(last_ts);
                let mut remaining = Duration::from_millis(delay_ms);

                // Sleep the required delay in small chunks so we can react to pause / stop
                while remaining > Duration::ZERO {
                    if !is_playing.load(Ordering::SeqCst) {
                        return;
                    }
                    if is_paused.load(Ordering::SeqCst) {
                        // Frozen while paused – do not consume remaining time
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    let chunk = remaining.min(Duration::from_millis(50));
                    thread::sleep(chunk);
                    remaining = remaining.saturating_sub(chunk);
                }

                if !is_playing.load(Ordering::SeqCst) {
                    break;
                }

                last_ts = rec.timestamp_ms;

                let event_type = match rec.event {
                    SerializableEventType::MouseMove { x, y } => EventType::MouseMove { x, y },
                    SerializableEventType::ButtonPress(b) => EventType::ButtonPress(b.into()),
                    SerializableEventType::ButtonRelease(b) => EventType::ButtonRelease(b.into()),
                    SerializableEventType::Wheel { delta_x, delta_y } => {
                        EventType::Wheel { delta_x, delta_y }
                    }
                };

                // Simulate the event. Errors are common if the target app rejects input.
                let _ = simulate(&event_type);
            }

            is_playing.store(false, Ordering::SeqCst);
            is_paused.store(false, Ordering::SeqCst);
        });
    }
}

impl eframe::App for MacroApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Detect when playback finishes
        if !self.is_playing.load(Ordering::SeqCst) && self.status.starts_with("▶️") {
            self.status = format!(
                "✅ Playback finished. {} events • {:.1}s",
                self.event_count, self.duration_secs
            );
        }

        // Live status while playing (including pause)
        if self.is_playing.load(Ordering::SeqCst) {
            if self.is_paused.load(Ordering::SeqCst) {
                self.status = "⏸ Paused  (press F2 to resume)".to_string();
            } else if !self.status.starts_with("⏸") {
                self.status = "▶️ Playing back... (F1 pause / F2 resume)".to_string();
            }
            ctx.request_repaint_after(Duration::from_millis(150));
        }

        // Live update while recording
        if self.is_recording.load(Ordering::SeqCst) {
            if let Ok(events) = self.recorded_events.lock() {
                self.event_count = events.len();
            }
            if let Ok(guard) = self.record_start.lock() {
                if let Some(start) = *guard {
                    self.duration_secs = start.elapsed().as_secs_f64();
                }
            }
            self.status = format!(
                "🔴 Recording... {} events • {:.1}s",
                self.event_count, self.duration_secs
            );
            // Keep UI responsive / live counter
            ctx.request_repaint_after(Duration::from_millis(80));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(12.0);
                ui.heading("🖱️ Mouse Macro Recorder");
                ui.add_space(8.0);

                ui.label(egui::RichText::new(&self.status).size(16.0));
                ui.add_space(18.0);

                // Record / Stop row
                ui.horizontal(|ui| {
                    ui.add_space(30.0);

                    let can_record = !self.is_recording.load(Ordering::SeqCst)
                        && !self.is_playing.load(Ordering::SeqCst);

                    if ui
                        .add_enabled(
                            can_record,
                            egui::Button::new("▶  Start Record")
                                .min_size(egui::vec2(130.0, 42.0)),
                        )
                        .clicked()
                    {
                        self.start_recording();
                    }

                    ui.add_space(12.0);

                    let can_stop = self.is_recording.load(Ordering::SeqCst);
                    if ui
                        .add_enabled(
                            can_stop,
                            egui::Button::new("⏹  Stop Record")
                                .min_size(egui::vec2(130.0, 42.0)),
                        )
                        .clicked()
                    {
                        self.stop_recording();
                    }
                });

                ui.add_space(14.0);

                // Play button
                ui.horizontal(|ui| {
                    ui.add_space(90.0);
                    let can_play = !self.is_recording.load(Ordering::SeqCst)
                        && !self.is_playing.load(Ordering::SeqCst)
                        && self.event_count > 0;

                    if ui
                        .add_enabled(
                            can_play,
                            egui::Button::new("⏯  Play Back")
                                .min_size(egui::vec2(160.0, 42.0)),
                        )
                        .clicked()
                    {
                        self.play_back();
                    }
                });

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(6.0);

                ui.label(format!("Events: {}", self.event_count));
                ui.label(format!("Duration: {:.1} seconds", self.duration_secs));

                ui.add_space(10.0);
                ui.small("• Records mouse movement, left/right/middle clicks and wheel");
                ui.small("• Supports recordings of 30+ minutes (memory efficient)");
                ui.small("• Hotkeys: F1 = Pause playback • F2 = Resume playback");
                ui.small("• Tip: Run as Administrator if playback fails in some apps");
                ui.small("• Built with Rust + egui + rdev");
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 340.0])
            .with_min_inner_size([420.0, 340.0])
            .with_resizable(false)
            .with_title("Mouse Macro Recorder"),
        ..Default::default()
    };

    eframe::run_native(
        "Mouse Macro Recorder",
        options,
        Box::new(|_cc| Ok(Box::new(MacroApp::new()))),
    )
}