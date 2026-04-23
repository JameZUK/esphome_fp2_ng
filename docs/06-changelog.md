# Changelog (esphome_fp2_ng)

Changes from the upstream [hansihe/esphome_fp2](https://github.com/hansihe/esphome_fp2).

## 2026-04-23 — Fall detection compliance audit and cleanup

Ghidra audit of stock FW1 (`fp2_aqara_fw1.bin`) against the driver's
fall-detection code. Finding: only one of the four fall SubIDs we
WRITE is genuinely in stock's protocol surface; the two "fall overtime"
SubIDs we RX are not fall events at all.

**What's real in stock (confirmed by dispatch-table/handler addresses):**

| SubID | Direction | dtype | Stock handler | Notes |
|---|---|---|---|---|
| 0x0123 FALL_SENSITIVITY | ESP→radar | U8 | `HandleCloud_Write_Dispatcher` idx 5 @ 0x400e36e1 | Clamped 0..3 (`bltui a10, 0x4`) |
| 0x0121 FALL_DETECTION_RESULT | radar→ESP | U8 | RAM dispatch 0x3ffb13a0 → 0x400e5388 | FW2 emit at radar 0x0001db92 |
| 0x0124 | radar→ESP | U8 | fall_overtime_report_period ack | Config echo only, cosmetic |

**What was invented on our side (not on the wire):**

- `FALL_OVERTIME_PERIOD = 0x0134` BLOB2 U32 — WRITE removed. FW1 MSS
  dispatcher routes 0x0134 to its unknown-SubID error path (verified
  via `FUN_00009718` control flow — lands at 0x9BFC: `movw r2, #0x59f;
  b 0x9db0`). Confirmed dead on the wire.
- `FALL_OVERTIME_DETECTION = 0x0135` / `FALL_OVERTIME_REPORT = 0x0136` —
  not fall events on the ESP side either. 0x0135's stock handler
  (0x400e11ac) reads a u16 calibration/version value ("13.25.85");
  0x0136's stock handler (0x400df760) is a 3-byte stub. Our
  `fall_overtime_sensor_` was wired to SubIDs that never fire.

**Correction (radar-side verification):** Two SubIDs we initially removed
are actually real — the stock ESP simply doesn't use them, but the
**radar MSS accepts them directly**:

- `FALL_DELAY_TIME = 0x0179` U16 — FW1 MSS handler at `0x00026200`
  decodes u16 payload, stores to config offset `+0x290`, logs
  `"fall_delay_time: %d\n"`. Functional WRITE. **Re-instated.**
- `FALLDOWN_BLIND_ZONE = 0x0180` BLOB2 40B — FW1 MSS handler at
  `0x0001da24` memcmp's 40 bytes at config `+0x1c`, memcpy's payload
  if changed, sets update flags at `+0xa4`/`+0xa5`. Functional WRITE.
  **Re-instated.**

Upstream corroboration: hansihe's PROTOCOL.md lists 0x0134/0x0135 as
RW attributes, and `decoded_conf_zone.txt` in the same repo captured
a live stock trace of `fall_detection_sensitivity (0123) = 1` during
normal Aqara-app setup — so "1" is the real stock-in-practice default
(driver default matches).

### Code changes

- **Remove three dead WRITEs** (0x0134, 0x0179, 0x0180) from the init
  burst. YAML options retained as no-ops for config backwards-compat
  (existing YAMLs don't break); `dump_config` warns when each is set.
- **Neuter the 0x0135 / 0x0136 RX handlers** — no longer publish to
  `fall_overtime_sensor_`. Sensor entity retained but will now stay
  "unknown"; warning logged at setup if configured.
- **Clamp `fall_detection_sensitivity` to 0..3** in the setter, matching
  stock's radar-side validation (`bltui a10, 0x4` in
  `HandleCloud_Write_Dispatcher`). Default stays at **1** — this is the
  value captured in a live stock trace (`decoded_conf_zone.txt` in the
  upstream RE repo: `WRT> fall_detection_sensitivity (0123) Seq:10 : 1`),
  reflecting what the Aqara app writes during normal setup. The
  factory-fresh RAM value is 0 (zero-init), but no FP2 in field use
  runs with 0 — the app always writes 1 after pairing.
- Clean up 0x0121 comment — drop unverified "type A / type B"
  interpretation; treat as raw u8 boolean.
- Fix stale comment claiming "Actual fall detection uses SubID 0x0306"
  (it was fiction; no firmware emits 0x0306).


## 2026-04-22 — Sleep Monitoring working end-to-end: `emulate_stock` flag + vitals on SubID 0x0159

### Definitive fix: stop the init burst in Sleep Monitoring, parse the right SubID

Two separate issues were both blocking vitals output; together they explain
every previous symptom.

**1. Our init WRITE burst was disrupting FW3 DSS track allocation.**

Ghidra deep-trace of `fp2_aqara_fw1.bin` (2026-04-22) confirmed the stock ESP
firmware emits **zero UART WRITEs** on radar-ready:
- `boot_init_main @ 0x400de62c` loads NVS, allocates buffers, publishes cloud
  attrs — does not touch UART
- `radar_ready_init_state @ 0x400e6350` (one-shot post-boot init) emits no
  WRITEs, only sets a "cloud channel ready" latch
- `after_radar_ready_poll @ 0x400e62b0` (triggered on radar heartbeat) calls
  `lazy_read_and_publish_state @ 0x400e5c50` which emits **READs** (opcode=1)
  for 0x0102 / 0x0116 / 0x0128 only when the cached byte is zero
- All radar WRITEs are forwarded from cloud-initiated ZCL writes via
  `HandleCloud_Write_Dispatcher @ 0x400e3399`

Our driver's 15+ WRITE init burst (MONITOR_MODE, FALL_SENSITIVITY,
LOCATION_REPORT_ENABLE, THERMO_EN, sleep-zone params, etc.) has no stock
analog, and its timing relative to FW3's DSS boot was breaking GTrack's
ability to allocate a track.

Added `emulate_stock` YAML flag. Gated the init burst behind
`!(emulate_stock_ && sleep_mode_active_)` — Zone and Fall modes still get the
full init (empirically they need it, and don't hit the GTrack issue); Sleep
Monitoring skips the burst and keeps whatever config is in radar flash from
the previous WORK_MODE save.

**2. Vitals were being parsed from the wrong SubID.**

Prior driver code expected HR and BR on SubID 0x0117 in FW3, as a 100×-scaled
u16 big-endian pair inside a 14-byte per-target block. Decompiling
`vitals_hr_br_emitter @ 0x00006c84` in `fp2_radar_vitalsigns.bin` showed the
function emits **both** 0x0117 (at `0x00006e2c`) and 0x0159 (at `0x0000701a`)
— but:

- 0x0117 is gated on `config+0xb8 == 1` (LOCATION_REPORT_ENABLE), AND
  `target_count > 0`, AND a frame counter `+0x28 > 15`, AND motion/state
  flags non-zero. For a stationary sleeper the counter rarely climbs and the
  state flags rarely align — 0x0117 almost never fires.
- 0x0159 is **not gated on +0xb8**. It fires every ~6 s whenever GTrack has
  a track. It carries a 12-byte payload: `[tid][0][0][HR_bpm u8][0][HR_conf]
  [BR_bpm u8][0][BR_conf][sleep_state][sleep_stage][event]`. HR and BR are
  **direct u8 bpm, not scaled**.

Switched the driver's `AttrId::SLEEP_DATA` handler to decode 0x0159's bytes
[3] and [6] directly and publish to `heart_rate_sensor_` /
`respiration_rate_sensor_`. The old 0x0117 FW3 branch is retained as
diagnostic-only logging (so we can still observe it if it does fire).

**3. Heart rate deviation is not emitted by the radar.**

The `heartDev` and `breathDev` slots in the 0x0117 15-byte payload are always
zero in FW3 emit. 0x0159 has no deviation field at all. Implemented
`heart_rate_deviation` as an ESP-side rolling population standard deviation
over the last 10 HR samples from 0x0159 (~60 s at 6 s cadence). Cleared on
presence loss.

### Workflow

Setup recipe now in [04-esphome-component.md](04-esphome-component.md) and
[../README.md](../README.md#sleep-monitoring-setup):

1. `emulate_stock: true` in YAML, flash
2. Cycle Operating Mode: Zone Detection → wait ~15 s → Sleep Monitoring
3. Climb into bed with deliberate motion (GTrack needs centroid radial
   velocity > 0.1 m/s to allocate the track — a person who lies still from
   a distance won't get tracked)
4. Once allocated, `stateParam sleep2free=9000` keeps the track alive for
   ~7.5 min of stillness, so ordinary sleep behaviour works fine

### Code changes

- `components/aqara_fp2/__init__.py`: add `CONF_EMULATE_STOCK` schema entry,
  wire setter
- `components/aqara_fp2/fp2_component.h`: `emulate_stock_` member, HR ring
  buffer (`HR_WINDOW_SIZE_=10`), setter
- `components/aqara_fp2/fp2_component.cpp`:
  - Gate init burst on `!(emulate_stock_ && sleep_mode_active_)`
  - Remove the vestigial LOCATION_REPORT_ENABLE=1 pre-WORK_MODE WRITE that
    was added for the 0x0117 path (kept only because 0x0159 isn't gated on
    `+0xb8`)
  - Rewrite `AttrId::SLEEP_DATA` handler: parse tid/HR/BR/confs/state/stage/
    event from 0x0159 byte layout; publish HR and BR; update the HR ring
    buffer and publish population std-dev to `heart_rate_dev_sensor_`
  - `handle_location_tracking_report_` FW3 branch: stop publishing HR/BR
    sensor values; keep diagnostic logging so 0x0117 is still observable
  - `dump_config`: add the `Emulate Stock` line
- Commits: `52c3e18`, `d73143c` (superseded), `59cdebe`, `1dd817f`

### Verification

An overnight soak-test confirmed continuous HR, BR, and HR-deviation output
across a full ~8 h sleep window:

- **Heart rate** — resting baseline in the high 50s / low 60s bpm, with
  typical sleep-cycle drift down into the low 50s during deep sleep and
  transient rises into the 70s on stirring events. Typical resting adult.
- **Respiration rate** — steady around 14-18 br/min through most of the
  night, dropping into the low teens during deep-sleep phases. Textbook.
- **Heart-rate deviation** — near-zero (< 1 bpm std-dev) during stable
  sleep; rose to 3-5 bpm during HR transitions and returned to baseline
  within a minute or two.

Track-loss gaps correlated with expected re-orientation events (rolling out
of the bed region, etc.) and the track was re-allocated cleanly on return.
No driver-side errors or dropouts.

### Later 2026-04-22 — Sleep mode presence-state lifecycle

Follow-on work after the vitals fix to make `global_presence`,
`sleep_presence`, and the vitals sensors behave correctly through the
full in-bed → out-of-bed → empty-room cycle.

- **Cross-trigger** — any occupancy signal (0x0159 frame, 0x0167=1,
  0x0171=1) asserts `global_presence` ON and stamps a watermark. Covers
  the HR=0 FFT warm-up phase at mode-entry (the first ~20-30 s after FW3
  boot) by triggering on any of the three signal types, not just HR>0.

- **0x0104=0 suppression in sleep mode** — FW3 can emit 0x0104=0 for a
  stationary sleeper even while GTrack has an active track and 0x0159
  is streaming. If the watermark is < 30 s old, the clear cascade is
  dropped rather than publishing false.

- **45 s re-init preservation** — the second init (post-boot) was
  unconditionally publishing `global_presence`, `sleep_presence`, and
  `sleep_state` to OFF/none as part of a "reset state" block. Observed
  live: user in bed, sleep_presence cross-triggered ON at t=32 s, both
  sensors flattened at t=45 s. Fixed by skipping the OFF publishes for
  those three sensors when the watermark is fresh.

- **Quiet-timeout auto-clear** — once GTrack releases the track, FW3
  stops emitting any presence signal (no 0x0159, 0x0167, 0x0171, 0x0104
  — only the 0x0102 heartbeat). Sensors would otherwise stay latched at
  their last-seen ON value forever. New loop-tick check clears all
  sleep-mode sensors after 60 s of radar silence. Tunable via
  `SLEEP_QUIET_TIMEOUT_MS_`.

- **Temperature READ response dispatch** — FW3 does not push unsolicited
  0x0128 temperature reports. Our init-time READ returns a value, but the
  op=4 RESPONSE handler previously only logged `[READBACK]` without
  calling the per-SubID publisher. Added a small switch so TEMPERATURE
  responses also populate `radar_temperature`. Still one-shot per mode
  cycle (no periodic refresh).

- **Documentation:** status-LED optical cross-talk with the OPT3001
  ambient light sensor documented in `01-hardware.md` and
  `04-esphome-component.md`. Stock firmware's `lux_acc_led_onoff`
  dynamically dims the LED against ambient lux; the ESPHome driver does
  not replicate it.

Commits: `7a05009`, `3a6614e`, `0ee6742`, `239e24f`, `56f986e`,
`e7e5a4e`, `2188c9c`.

### Superseded (preserved for history)

The 2026-04-21 entries below chase two wrong theories that were ruled out:
GTrack velocity gate (partially right — the gate exists, but gating it was
downstream of the real problem) and SLEEP_REPORT_ENABLE=1/heartbeat 0x0203
sync (SLEEP_REPORT_ENABLE turned out to be a pure no-op in FW3; 0x0203 sync
is useful but doesn't unblock vitals on its own). The actual blocker was
our own init burst + wrong SubID decode, documented above.

## 2026-04-21 — Sleep Monitoring fix: SLEEP_REPORT_ENABLE=1, heartbeat 0x0203 sync

### Actual root cause found via stock ESP32 firmware diff

After two false hypotheses (row-noise self-cal, then GTrack velocity gate —
both rabbit holes chasing problems in the RADAR firmware), the real cause was
in the ESP32 ↔ radar protocol. Aqara's **radar firmware is a known-good
production input**; the gap was in what our ESPHome driver sends to it vs
what Aqara's stock ESP32 sends.

Disassembling `fp2_aqara_fw1.bin` (stock ESP32, Xtensa) against our driver's
sleep-mode-transition command sequence revealed two concrete differences:

1. **`SLEEP_REPORT_ENABLE (SubID 0x0156)` must be `1`, not `9`.** Stock cloud
   handler at `FUN_400e3399 @ 0x400e3751` rejects any value ≥ 2 (verified
   disassembly: `bltui a10, 0x2, …`). And the stock heartbeat-sync gate at
   `radar_sw_version @ 0x400e4f28` compares the stored flag `== 1`, not
   `== 9`. The SBL firmware selector DOES accept `byte[4] == 1` as a FW3
   trigger — so sending value 1 is both what stock does AND what routes to
   FW3 boot. Our previous "=9" was based on a misreading of the SBL selector
   (which also accepts `byte[2] == 9` as a second FW3 condition — and that's
   the path that fires when we write `WORK_MODE = 9`, which is orthogonal).

2. **Heartbeat-driven `WRITE 0x0203` was one-shot, should be per-heartbeat.**
   Stock's `heartbeat_config_sync @ 0x400decd4` fires on every incoming
   radar heartbeat (0x0102) whenever sleep_report_enable==1 OR work_mode==9.
   Our driver was sending 0x0203 only once at init and never again. Without
   this periodic keep-alive, the radar's sleep state machine appears to
   stall. The payload is a u8 counter — stock reads it from persistent NVS
   (config-version counter); our driver uses a simple incrementing u8.

### Previous hypotheses (now superseded, preserved for history)

**GTrack velocity allocation gate (2026-04-21 afternoon)**: hypothesized that
GTrack's `velocityThre=0.1 m/s` in `allocationParam` blocked track creation
for motionless sleepers. Confirmed the gate exists in TI SDK source
(`gtrack_module.c:190-192`), but empirical testing (user moved into bed
during mode transition) didn't unlock vitals — so the gate isn't reachable
from our driver's command sequence anyway, because the radar's data pipeline
never starts emitting. The missing `WRITE 0x0203` keep-alive is upstream of
GTrack.

**Row-noise self-calibration (2026-04-21 morning)**: hypothesized that FW3
DSS's noise floor calibration baked the sleeper into background. Turned out
to be from an older ancestor codepath (`oddemo_heatmap`, `mmVital-Signs`
demo) that Aqara's FW3 doesn't use. Aqara's DSS uses `capon3d_vitalsigns`
with dual CFAR, which has no equivalent self-cal trap.

### Code changes

- `components/aqara_fp2/fp2_component.cpp`:
  - `set_operating_mode`: `SLEEP_REPORT_ENABLE` value `9` → `1`; comment
    block rewritten to explain stock's cloud-handler validation and the
    heartbeat gate
  - `handle_parsed_frame_` (RADAR_SW_VERSION/0x0102 heartbeat case): when
    `sleep_mode_active_ && init_done_`, enqueue `WRITE 0x0203 = counter++`
    to mirror stock's `heartbeat_config_sync`
- `components/aqara_fp2/fp2_component.h`: added `zone_config_sync_counter_`

### RE notes added to 07-firmware-analysis.md

Added the stock ESP32 cloud-handler table (SubID → handler addr → dtype →
clamp), the heartbeat-sync gate logic, and function addresses for
reproducibility.

## 2026-04-21 (earlier) — FW3 silent-all-night cause found: GTrack velocity allocation gate

### Initial hypothesis (2026-04-21 morning): row-noise self-calibration — WRONG

First hypothesis: FW3's DSS averages its noise floor over the first ~64 frames
and subtracts it forever, baking an already-present sleeper into background.
This was based on reading the `oddemo_heatmap` code from a public mmVital-Signs
ancestor. Empirical test (user applied the "clear FOV then switch mode"
workflow) did NOT restore vitals — so the hypothesis was wrong.

### Correct root cause (2026-04-21 afternoon): GTrack allocation velocity gate

Deeper string extraction from `fp2_radar_vitalsigns.bin` revealed Aqara uses
the **capon3d_vitalsigns** (not oddemo_heatmap) DPC, plus TI's full **GTrack
group tracker** (`src/gtrack_module.c` in the MSS binary). Hard-coded CLI
defaults in the MSS include:

```
allocationParam 20 100 0.1 10 0.5 20
# snrThre=20, snrThrObscured=100, velocityThre=0.1, pointsThre=10, maxDistThre=0.5, maxVelThre=20
```

TI's `gtrack_moduleAllocate()` (verified in mmwave_sdk_01_02_00_05 source,
line 190-192) requires three conditions to allocate a new track:

```c
if (allocNum > pointsThre           // >10 points in cluster
 && allocSNR > snrThre               // cluster SNR sum > 20
 && fabs(un[2]) > velocityThre)     // |centroid velocity| > 0.1 m/s
```

**A sleeping person has radial velocity ≈ 0** (chest motion is sub-mm per
frame; bulk Doppler is 0). The cluster velocity fails the 0.1 m/s gate.
**No track is ever allocated**, `numCurrentTargets` stays 0 in the
`VS_Data_MSS2DSS` shared struct, and the 0x0117 emit gate
(`target_count != 0` inside FW3 MSS `FUN_00006c84`) suppresses all output.

Once a track IS allocated (via gross motion), `stateParam 2 50 50 900 50 9000`
keeps it alive via long timers: `static2free=900` frames (~45s) and
`sleep2free=9000` frames (~7.5 min). So the sleeper can lie still for the
whole night once tracked.

### Documentation: Operating Modes and Sleep Monitoring

Added [04-esphome-component.md](04-esphome-component.md) "Operating Modes"
section documenting scene_mode ↔ firmware mapping and the sleep-mode workflow
requirement (get out of bed → switch mode → wait for restart → **move as you
get into bed** so the tracker allocates). Once allocated the track persists
through the static2free/sleep2free timers.

### Documentation: Operating Modes and Sleep Monitoring

Added [04-esphome-component.md](04-esphome-component.md) "Operating Modes"
section documenting scene_mode ↔ firmware mapping and the sleep-mode workflow
requirement (cycle mode with empty FOV, wait ≥5s, then enter the bed). Heart
Rate / Respiration sensors then take another ~15-30s to converge as FFT
buffers fill.

### RE corrections

- **SLEEP_REPORT_ENABLE (0x0156) WRITE is a no-op in FW3.** The dispatcher
  `FUN_00009e80` routes 0x0156 WRITE to `FUN_0001fbf8`, which only reads flash
  params and logs them — it does not write any config field. Prior notes that
  speculated writing 0x0156=9 activates FW3 were wrong. FW3 is activated
  exclusively via `WORK_MODE=9` (SubID 0x0116) which writes `scene_mode` to
  SBL byte[2]. The driver's `SLEEP_REPORT_ENABLE=9` write is decorative.
- **SBL firmware-selection condition corrected**: `sleep_enable == 1`
  (not 9) OR `work_mode == 9`. Only the `work_mode` branch is reachable in
  practice; nothing in FW3 ever writes `config+0xb6c` (source of SBL byte[4])
  to non-zero.
- **SubID map corrections verified via decompile**: 0x0178 → OVERHEAD_HEIGHT
  (writes `+0xbb0`), 0x0177 → SLEEP_BED_HEIGHT (writes `+0xb92`), 0x0173
  writes `+0xba1` (unknown semantics, not OVERHEAD_HEIGHT as prior notes
  claimed). Driver's `AttrId` enum values are correct.
- **FALL_SENSITIVITY=1 (SubID 0x0122) activates bed-region geometry gate**
  via `FUN_0002dca8` which tests `config+0x510==1 OR (+0x510==2 AND
  +0x5b8 ∈ {4,7})`. Driver already sends this at init.
- **Emit rate limiter corrected**: the counter at `config+0x28` inside
  `FUN_00006c84` is a rate limiter, not a stabilization window. Resets only
  on successful emit, not on target loss. First emit after target reappears
  is immediate; subsequent emits at ~16-frame cadence.

### FW3 architecture

- `fp2_radar_vitalsigns.bin` is the MSS slice only; full FW3 packaged as three
  RPRC subimages: `fw3_rprc0_type4.bin` (MSS, 210KB), `fw3_rprc1_typec.bin`
  (DSS_DATA shared blob, 247KB — identical across FW1/FW2/FW3),
  `fw3_rprc2_typed.bin` (DSS_APP vital-signs C674x code, 262KB).
- Public TI-ancestor sources cloned to `/tmp/vital_signs_people_tracking/`
  for reference (exact `Vital_Signs_With_People_Tracking` is TI-proprietary
  binary-only; `multiple-person-vital-signs/` has the closest algorithmic
  lineage).

### Updated files

- `docs/04-esphome-component.md`: added Operating Modes section with the
  Sleep Monitoring workflow; corrected sleep-sensor SubID table.
- `docs/07-firmware-analysis.md`: corrected SBL firmware-selection logic;
  added "Completed: FW3 MSS + DSS — Vital Signs Activation and Row-Noise
  Trap" section; fixed SubID data-format table.
- `docs/02-uart-protocol.md`: SubID OVERHEAD_HEIGHT / SLEEP_BED_HEIGHT
  corrections.
- `/config/esphome/fp2.yaml`: added comment block explaining the Sleep
  Monitoring workflow requirement.
- `components/aqara_fp2/fp2_component.cpp`: no code changes today; current
  commits (d8944c0 scene_mode=9 + vitals decoder, 7eabaab debug dump, d6225d6
  SLEEP_REPORT_ENABLE=9) remain correct as-is. SLEEP_REPORT_ENABLE=9 write
  is now known to be a no-op but is kept for cloud-symmetry.

## 2026-04-18 — Ghidra-verified SubID corrections, architecture clarification, XMODEM OTA hardening

### Critical corrections to prior claims

Several entries below this one contained claims that this session's Ghidra
work has now **falsified**. The corrections are authoritative — they're
derived from decompiling the specific binary that actually handles each case,
not from cross-firmware speculation.

- **Fall detection SubID is `0x0121`, not `0x0306`.** The 2026-04-15 entry
  claimed `FALL_DETECTION_RESULT = 0x0306` and that `0x0121 = angle sensor`.
  Both are wrong. Decompile of FW2 MSS (the *fall-detection* firmware —
  previously never examined) at `FUN_0001db70` shows the emission call
  `FUN_00011d3c(5, 0x121, 0, &state_byte)` with the adjacent debug string
  `"fall_detection:%d"`. Payload is uint8: `0=clear, 1=fall type A, 2=fall type B`.
  The stock ESP dispatch table `0x3ffb13b8` binds `0x0121` →
  `radar_fall_detection`. No MSS binary (FW1, FW2, FW3) emits `0x0306` at all.

- **Heart rate / respiration arrive on `SubID 0x0117` in mode 9, not floats in
  `0x0159`.** The 2026-04-15 SLEEP_DATA parser in `fp2_component.cpp` decoded
  12 bytes of `0x0159` as three IEEE-754 LE floats (`heartRate`, `breathRate`,
  `heartDev`). That matches TI's reference Vital-Signs debug strings
  (`"heartRate = %.0f ..."`), but those strings go to a separate debug-UART
  `printf`, **not** to the 0x55/0x01 protocol framer. Decompile of FW3
  (vitalsigns) `FUN_00006c84` at the 0x117 emission site shows:

  ```
  blob[0]    = 1 (fixed header byte)
  blob[1]    = track_id
  blob[2..3] = round(HR_bpm     * 100) as uint16 big-endian
  blob[4..5] = round(BR_per_min * 100) as uint16 big-endian
  blob[6..14]= zero padding
  ```

  Scaling constant `100.0f` verified in firmware data (`0x42C80000`).
  The 0x0159 blob is a parallel 12-byte per-byte metadata struct:
  `tid / count / motion / sleep_stage / posture / confidence / bed_state /
  conf2 / ...` — NOT floats. Old parser would have published garbage to the
  HR/BR sensors if sleep ever engaged. New parser in `fp2_component.cpp`
  reads 0x117 mode-aware and logs 0x159 bytes verbatim (MEDIUM confidence
  per-field naming). Heart-rate-deviation is NOT emitted by stock vitalsigns
  firmware — that sensor will stay unpopulated.

- **The three radar firmware images are NOT "the same firmware with different
  config"** (as the 2026-04-15 entry claimed). They have genuinely distinct
  MSS application binaries (type-0x04 RPRC sub-images within each MSTR
  container). Sizes: FW1 MSS = 228,544 B (Zone, mode 3), FW2 MSS = 142,720 B
  (Fall, mode 8), FW3 MSS = 210,560 B (Sleep, mode 9). Each has its own
  dedicated DSP image (types 0x0a/0x0b/0x0d). Only the 247,424 B type-0x0c
  sub-image (probably TI HSM/security runtime) is byte-identical across all
  three. Previous Ghidra analysis had only loaded FW1 MSS and FW3 MSS — FW2
  was never examined, which is why the `0x0121 → fall_detection` mapping
  remained undiscovered for so long.

- **Ghidra-binary naming**: `fp2_radar_mss.bin` ≈ FW1's RAM image (Zone).
  `fp2_radar_vitalsigns.bin` ≈ FW3's RAM image (Sleep). FW2's MSS (Fall) was
  extracted to `analysis/subimages/fp2_radar_mss_fw2.bin` this session and
  loaded fresh. The 2026-04-16 entry's "`fp2_radar_mss.bin` is misnamed — it
  is FW1's DSS content" is also wrong — sizes match FW1's combined RAM image
  (SBL + MSS + shared + DSP), not FW1's DSS alone.

### Code changes landed

- `radar ota: drop ACK gate, send trigger frame one-shot` (`0364734`) — the
  `0x0127` OTA trigger is fire-and-forget; stock firmware does not wait for a
  cluster ACK. Prior implementation waited, timed out, and aborted before the
  XMODEM 'C' handshake ever arrived. Probe test now confirms `'C'` within
  ~360 ms.
- `radar ota: flush UART after every xmodem block and EOT` (`4eea6be`) —
  `write_array()` only pushes into the ESPHome UART ring buffer; without
  `flush()` the bytes dribble out across many loop iterations and the radar's
  internal byte-gap timeout fires, triggering NAK/CAN. Adding `flush()` in
  `ota_send_current_block_()` and `ota_send_eot_()` removed the NAK storms.
- `radar ota: run xmodem transfer in a dedicated FreeRTOS task` (`c1db4ab`) —
  previously, the ACK→next-block round-trip ran inside the cooperative
  ESPHome main loop and got blocked by HA API / telemetry ticks. Moving the
  transfer into `fp2_ota_xfer` at `tskIDLE_PRIORITY+2` removes that shared
  scheduling contention.
- `debug: raw UART trace window on mode switch` (`40b39bb`) — 15 s trace of
  every TX/RX byte in hex when `set_operating_mode()` fires. Used this session
  to prove that `WORK_MODE=0x0116` writes DO cause the radar to ACK and soft-
  reboot into the new mode.
- `fall detection: fix SubID 0x0306 -> 0x0121` (`a703c9c`) — enum correction
  plus handler comment update.
- `vitals: decode HR/BR from SubID 0x0117 in sleep mode` (`dbc03ac`) —
  `handle_location_tracking_report_` is now mode-aware; in sleep mode it
  parses the 15-byte blob as vitals instead of target-tracking. SLEEP_DATA
  parser rewritten for per-byte metadata layout.

### Open questions (honest accounting of what we did NOT solve)

- **Sleep mode produces no events even after all the above fixes.** Aqara's
  product FAQ (https://www.aqara.com/eu/product/presence-sensor-fp2/faq/)
  says sleep monitoring requires "sleep space intelligent learning" as a
  mandatory setup step. Our driver never sends that command. The vitalsigns
  binary has `"learn complete!!!"` at `0x677c` and accumulator `FUN_00006390`
  that writes a learned threshold to flash via `FUN_0002cf28`, but the
  incoming SubID that *initiates* the learning phase is not locatable via
  static RE — no xrefs to the learning state functions, no stored pointers
  to the candidate addresses. Dynamic analysis (UART capture during a real
  Aqara-app sleep-setup flow) is the realistic next step.

- **Fall detection doesn't fire from "lying down" tests.** The fall ML state
  machine in FW2 MSS (`FUN_000022b8`) requires a ballistic upright→horizontal
  transition pattern plus low post-impact motion. It will not trigger from
  calm lying down, sitting, or sleeping. Real-fall validation still pending.

- **Heart-rate / respiration / heart-rate-deviation remain unobtainable in
  practice** until sleep-space-learning is solved — mode-9 with an
  un-calibrated zone keeps the presence-count at zero and the sleep task's
  emission gates never open. Once learning is solved, the 0x0117 decoder
  landed this session will populate HR/BR automatically.

- **Full radar OTA via XMODEM-1K remains slow and unstable.** The task-based
  transfer is stable for the first ~18–22 % of the 2,369 blocks, then the
  radar starts emitting CAN bytes and cancels. Root cause unknown — per-block
  turnaround of ~720 ms is radar-side, and stock Aqara's OTA is known (from
  user observation) to complete in under a minute. Speculation about shared
  QSPI flash, ROM-bootloader, or higher-baud modes was investigated and ruled
  out by Ghidra; the real mechanism of stock's fast OTA is still not known.
  For now, users who want to reflash a bricked radar image must persist
  through multiple cycles (each abort doesn't corrupt working images — the
  three active slots at `0x100000 / 0x2d2000 / 0x460000` are only overwritten
  after a successful EOT commit).

### MSTR sub-image extractor (new)

`analysis/subimages/` now contains each FW's type-0x04 RPRC body as a
separate `fwN_rprcM_type4.bin` file, stripped of the 32-byte RPRC header.
FW2's was imported into Ghidra for the fall-detection analysis this session.
The extraction was ad-hoc Python — not yet packaged as a script; future
work could extend `scripts/extract_radar_firmware.py` with a `--dump-subimages`
flag.

## 2026-04-16 — Three Radar Firmware Images Validated, SBL Safety Assessment

### RE Discoveries (Ghidra-validated)

- **Three distinct MSTR firmware images** in the `mcu_ota` partition (4MB),
  all CRC32-verified and structurally validated:
  - FW1 (MSS 65KB + DSS 683KB): Zone Detection — `Peoplecount.c`, fall area
  - FW2 (MSS 65KB + DSS 576KB): Fall Detection — DSP scoring, height estimation
  - FW3 (DSS 678KB, no SBL): Sleep/Vital Signs — heart rate, respiration, sleep stages
- **`fp2_radar_mss.bin` is misnamed** — it is FW1's DSS content, not the MSS boot loader.
  All Ghidra analysis was performed on the correct data despite the naming.
- **FW2's "deep learning"** is a small custom neural network (~9 layers, no ML framework).
  Contains `mylayer[].output_data`, `wide`, `high`, `outchannels` — likely a shallow
  fall/posture classifier. Not modern deep learning.
- **FW3 is standalone but has no SBL** — relies on the boot loader already on the radar.
  Built from TI mmWave Industrial Toolbox 4.11.0 Vital Signs demo.
- **All three share identical TI-RTOS runtime** (247KB, same SHA256) — same SDK build.
- **All three share Aqara UART protocol** (`communication.c`) — SubID handlers compatible.
- **String attribution verified**: "Deep learning" only in FW2, "Vital Signs" only in FW3,
  "Peoplecount" only in FW1. Cross-checked across all sections.
- **FW1's SBL has `SBL_WORK_MODE_OFFSET`** for multi-firmware switching. FW2's does not.
- **No direct mode-to-offset mapping table** found in stock ESP32 firmware.
  Mode selection uses SBL flash parameters.
- **OTA must use raw MSTR images** from mcu_ota, not extracted .bin files. CRC32 trailer
  (4 bytes) must be included. Extracted files have stripped headers and gap padding.
- **SBL safety assessment**: backup factory image fallback confirmed via string
  analysis. Image loaded to RAM and CRC-verified before execution. Authentication
  check exists (may block unsigned firmware). Partial write recovery and backup
  image isolation not yet verified — requires Ghidra decompilation of SBL.

## 2026-04-15 — Operating Mode Select, Fall Detection Fix, Scene Mode RE

### Documentation

- **4 operating modes documented** — Zone Detection (mode 3, wall), Fall Detection
  (mode 8, ceiling), Sleep Monitoring (mode 9, bedside), Fall + Positioning
  (mode 8 + tracking). All use same radar firmware with different config.
- **Two radar chirp configs** — Config A (10fps, wall) and Config B (6.67fps,
  ceiling/sleep). Selected on radar restart based on scene mode.
- **Mounting position requirements** — Fall detection needs ceiling, sleep needs
  bedside, zone detection works from wall/corner.
- **AI Learning** = simultaneous edge + interference auto-calibration.
- **Operating mode persists across reboots** — saved to ESP32 flash via
  ESPPreferences, restored on boot.

## 2026-04-15 — Fall Detection Fix, Sleep Mode Switch, Scene Mode RE

### Critical Fixes

- **Fall detection uses SubID 0x0306, not 0x0155 ontime** — The ontime field
  in 0x0155 is cumulative dwell time (0.15 * frame_count), non-zero for ANY
  presence. The actual fall signal is SubID 0x0306 (UINT8: 0/1) from the
  radar's fall state machine at offset +0x587/+0x589.

- **SubID 0x0121 is angle sensor revision, not fall detection** — Dispatch
  table confirms 0x0121 → `radar_angle_sensor_rev`. Fall handler is 0x0122
  (stock ESP32), actual signal is 0x0306 (radar).

### New Features

- **Sleep mode switch** — Toggle between presence detection (scene mode 3)
  and vital signs monitoring (scene mode 9). Uses WORK_MODE (0x0116) WRITE
  to trigger flash save + radar self-restart. Init skipped in sleep mode
  to prevent 0x01xx WRITEs from triggering mode 3.

### RE Discoveries

- **Scene mode state machine** (FUN_00013d9c): Mode 3/5 entry clears
  sleep_report_enable. Mode changes write to flash and self-restart.
- **FUN_000257d4** (scene mode reporter): Checks sleep_report_enable on boot,
  overrides scene_mode from 3 to 9 if set.
- **FUN_00025dfc** (SubID-to-scene mapper): 0x01xx + opcode!=1 → mode 3.
  Our ACKs (opcode 3) for 0x0117 were resetting to mode 3 and clearing sleep.
- **SLEEP_REPORT_ENABLE writes to RAM only** — flash write requires
  FUN_00013d9c (triggered by WORK_MODE SubID 0x0116).
- **Sleep zone params (0x0168/0x0169/0x0177/0x0178) are RAM-only** in the
  radar, lost on every reboot. Sent during normal init.
- **Vital signs (0x0159) come from DSS** (C674x DSP), not MSS. Only
  forwarded when radar is in scene mode 9.
- **Complete SubID sender enumeration**: All 30 callers of FUN_00019590
  mapped, including 0x0305 and 0x0306 in the 0x03xx range.

## 2026-04-14 — Presence Detection Fix, Fall Detection, Complete Feature Audit

### Critical Fixes

- **All three grids sent during init**: The radar requires edge (0x0107),
  interference (0x0110), and exit (0x0109) grids ALL sent during init or it
  silently suppresses presence/motion reports. The component now sends empty
  defaults when grids are not configured in YAML.

- **Double-init at 45 seconds**: The radar ACKs commands during its ~38-second
  boot sequence but does not apply them. Init is now sent twice: on first
  heartbeat (~3s) and again at 45 seconds. Both inits are identical.

- **Presence delay after OTA**: After OTA flash, the radar takes 2-5 minutes
  before producing presence/motion reports (0x0103/0x0104). Target tracking
  (0x0117) starts immediately. This is normal radar behaviour.

### New Features

- **Fall detection via 0x0155 PEOPLE_COUNTING**: Confirmed via Ghidra RE of
  both radar firmware (`FUN_00015624` sends 0x0155 with "Fall area: %d, %d"
  debug string) and stock ESP32 firmware (`radar_people_counting` at
  `0x400e04c4`). BLOB2 payload is 7 bytes:
  `[ZoneID:1] [PeopleCount:2 BE] [OntimeValue:4 BE]`.
  Non-zero ontime indicates a fall event. SubID 0x0121 is NOT sent by the radar.

- **Fall overtime detection (0x0135)**: Binary sensor for prolonged falls
  (person unable to get up). Triggers when fall persists beyond configured timeout.

- **Fall overtime period (0x0134)**: Configurable timeout in milliseconds.

- **Fall delay time (0x0179)**: Delay before confirming a fall event. Discovered
  via Ghidra handler table RE — `"fall_delay_time:%d"` debug string in radar firmware.

- **Falldown blind zone (0x0180)**: 40-byte grid (same 14x14 ASCII format) for
  fall detection exclusion zones. Extensively referenced in radar firmware with
  flash storage, validation, and deletion functions.

- **Sleep bed height (0x0177)**: Bed/mattress height config for sleep monitoring.
  Discovered via Ghidra — `"sleep_bed_height:%d"` in radar firmware.

- **Overhead/ceiling height (0x0178)**: Ceiling height config for spatial
  calibration. Handler `FUN_000265f4` stores at offset +0xbb0 in radar config.

- **Delete false targets (0x0160)**: Button to remove phantom/false targets
  from radar tracking.

- **Dwell time enable (0x0172)**: Now configurable (was hardcoded off).

- **Sleep mount position (0x0168)** and **sleep zone size (0x0169)**: Optional
  sleep monitoring configuration parameters.

- **Radar state diagnostic sensor**: Text sensor tracking boot sequence:
  Booting → Init sent → Re-init → Ready → Presence.

- **HW version capture (0x0101)**: Reads radar hardware version and appends
  to software version string. Note: radar does not respond to READ requests
  for this SubID in practice.

- **Radar debug log (0x0201)**: Captures debug strings from radar MCU when
  `debug_mode: true`. Radar's internal debug flag appears off by default;
  no known SubID to enable it.

### Card Improvements

- **Update throttling**: 250ms throttle on hass updates (was unthrottled)
- **Posture-aware targets**: S=standing, s=sitting, L=lying with glow effects
- **Auto-tracking**: `auto_tracking: true` enables target reporting when card loads,
  disables when navigating away
- **Info overlay**: Status bar overlaid on canvas bottom instead of below it
- **Removed console.log spam**: ~30 debug logs per update cycle removed

### RE Discoveries

- **0x0155 PEOPLE_COUNTING blob structure**: 7 bytes decoded via Ghidra analysis
  of both radar (`FUN_00015624`) and stock ESP32 (`0x400e04c4`) firmware
- **Fall detection path**: Radar's fall algorithm sends 0x0155, NOT 0x0121.
  Stock firmware derived 0x0121 from 0x0155 data.
- **Handler table SubIDs 0x0177-0x0180**: All four confirmed in both firmwares
  via Ghidra. Handler functions, debug strings, and cloud relay functions found.
- **Radar debug flag**: 0x0201 send function gated by flag at offset +0x587 in
  radar config struct. Flag is zero (off) by default.
- **HW_VERSION behaviour**: Radar has send function `FUN_00026a94` with
  `"Hardware_version:%d"` string but does not respond to READ requests.

## 2026-04-12 — OPT3001 Light Sensor, Auto-Calibration, I2C Fixes

### New Features

- **OPT3001 ambient light sensor**: Identified as TI OPT3001 at I2C address
  0x44 via I2C bus scan diagnostic. Driver reads lux every ~1s in continuous
  mode (800ms conversion, auto-range). Publishes on >5% change.
  Config: `light_sensor: name: "Ambient Light"` under `aqara_fp2_accel`.

- **Auto-calibration buttons**: Added `calibrate_edge` and
  `calibrate_interference` button entities. Pressing triggers
  `EDGE_AUTO_ENABLE` / `INTERFERENCE_AUTO_ENABLE` on the radar. Handlers
  receive the auto-detected grids, store them, apply to radar, and update
  card diagnostic sensors.

- **Complete SubID enum**: Added all 22 previously missing SubIDs from the
  protocol RE (43 total). Organized by category: system, detection, config,
  grids, auto-calibration, tracking, counting, posture, fall detection,
  sleep monitoring, temperature.

- **I2C bus scan diagnostic**: Scans all I2C addresses during `dump_config()`
  and logs found devices with candidate identifications. Runs after API
  connects so results appear in ESPHome logs (not just serial).

### Bug Fixes

- **I2C bus contention**: Added 5ms yield between accelerometer and OPT3001
  reads. Added `i2c_master_bus_reset()` on `INVALID_STATE`/`TIMEOUT` errors
  to recover the bus. Suppressed noisy warning logs for recoverable errors.

- **I2C bus scan timing**: Moved scan from `setup()` to `dump_config()` so
  results appear in API logs. Accel FreeRTOS task is suspended during scan
  to prevent contention.

### Documentation

- **Firmware analysis guide** (07-firmware-analysis.md): Complete RE workflow
  using Ghidra + bethington/ghidra-mcp + dynacylabs ESP32 flash loader.

- **Full protocol reference**: Updated 02-uart-protocol.md with all 43 known
  SubIDs and implementation status (Y/P/N).

### RE Discoveries (from stock firmware analysis)

- **Light sensor IC**: TI OPT3001 at I2C 0x44. Stock firmware source file:
  `apps/user/hal/acceleration_ambinent_light.c`. Uses NVS-stored calibration
  coefficients (lux_low_k/b, lux_high_k/b).

- **Radar OTA mechanism**: Uses XMODEM protocol over existing UART, NOT SOP
  pin toggling. Firmware stored in `mcu_ota` partition (4MB, sub_type 0xFE).
  SubID 0x0127 triggers bootloader mode. Source files: `radar_ota.c`,
  `xmodem.c`. Not yet implemented in ESPHome.

- **Full partition table**: nvs, otadata, phy_init, aqara_fw1 (2MB),
  aqara_fw2 (2MB), test (76KB), mcu_ota (4MB), fctry (24KB).

## 2026-04-11 — Initial Fork

### Bug Fixes

- **Switch fall-through in `handle_report_()`**: Every case in the report
  handler's switch statement used a pattern where `break` was inside an `if`
  block. If the payload size check failed, execution fell through to the next
  case, causing malformed packets to be misinterpreted as different report types.
  Fixed by moving `break` outside the `if` blocks for all affected cases:
  `RADAR_SW_VERSION`, `WORK_MODE`, `DETECT_ZONE_MOTION`, `MOTION_DETECT`,
  `PRESENCE_DETECT`, `ZONE_PRESENCE`.

- **Null pointer dereferences**: `global_motion_sensor_` and
  `global_presence_sensor_` were dereferenced without null checks in
  `handle_report_()`. If `global_zone` was configured without `motion` or
  `presence` sensors, these would crash. Added null checks.

- **PI constant typo**: `aqara_fp2_accel.h` defined PI as `3.141614159265`
  (extra "61" inserted). Corrected to `3.14159265358979`.

- **Dead accelerometer calibration**: `calculate_calibration()` computed
  correction values then immediately zeroed them out and returned, with the
  actual return/log statements unreachable. Removed the zeroing-out code to
  restore the intended behaviour.

- **ESP-IDF 5.5+ compilation error** (upstream issue #2): Migrated from the
  removed `driver/i2c.h` legacy API to `driver/i2c_master.h`. Used
  `i2c_master_transmit_receive()` for register reads (not `i2c_master_receive()`
  which would skip the register address write — a bug in the community-proposed
  fix).

- **Wall mounting mode card** (upstream issue #3): The Lovelace card had a
  placeholder coordinate conversion for wall mode (`target.x * 0.01`). The raw
  coordinate space is identical for all mounting positions, so applied the same
  proven conversion formula used for corner modes.

### New Features

- **Global people count sensor**: The `ONTIME_PEOPLE_NUMBER` report (SubID
  0x0165) was received and logged but never exposed as an entity. Added a
  `people_count` sensor option.

- **Per-zone people count sensors** (upstream issue #1): Added `zone_people_count`
  sensor option per zone. Works by cross-referencing target positions from the
  location tracking data (SubID 0x0117) against each zone's grid bitmap.
  Location reporting is automatically enabled when any zone has this sensor
  configured.

### Re-enabled

- **Zone motion handler**: The zone motion publish logic in `DETECT_ZONE_MOTION`
  was commented out, so per-zone motion binary sensors never updated. Uncommented.

### Cleanup

- Removed commented-out `add_zone()` dead code
- Removed remaining unreachable code in accelerometer calibration
