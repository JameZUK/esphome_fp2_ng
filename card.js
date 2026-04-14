/**
 * Aqara FP2 Presence Sensor Card for Home Assistant
 *
 * Configuration options:
 * - entity_prefix: (required) The entity prefix for the FP2 sensor (e.g., "sensor.fp2_living_room")
 * - title: (optional) Card title
 * - display_mode: (optional) "full" or "zoomed" - Default: "full"
 * - show_grid: (optional) Show grid lines - Default: true
 * - show_sensor_position: (optional) Show sensor position marker - Default: true
 * - show_zone_labels: (optional) Show zone labels - Default: true
 * - auto_tracking: (optional) Automatically enable target tracking when card loads - Default: false
 */
class AqaraFP2Card extends HTMLElement {
  constructor() {
    super();
    this.config = {};
    this.displayMode = "full";
    this.showGrid = true;
    this.showSensorPosition = true;
    this.showZoneLabels = true;
    this.gridSize = 14;
    this._lastRender = 0;
    this._pendingUpdate = null;
  }

  set hass(hass) {
    this._hass = hass;
    if (!this.content) {
      this.initializeCard();
    }
    // Throttle updates — radar streams at 2-3Hz but hass fires on ANY state change
    const now = Date.now();
    if (now - this._lastRender < 250) {
      if (!this._pendingUpdate) {
        this._pendingUpdate = setTimeout(() => {
          this._pendingUpdate = null;
          this._doUpdate();
        }, 250 - (now - this._lastRender));
      }
      return;
    }
    this._doUpdate();
  }

  _doUpdate() {
    this._lastRender = Date.now();
    if (!this._hass || !this.canvas) return;
    const data = this.gatherEntityData();
    this.updateLiveViewButton();
    this.renderCanvas(data);
    this.updateInfoPanel(data);
  }

  setConfig(config) {
    if (!config.entity_prefix) {
      throw new Error("You need to define entity_prefix");
    }
    this.config = config;
    this.displayMode = config.display_mode || "full";
    this.showGrid = config.show_grid !== false;
    this.showSensorPosition = config.show_sensor_position !== false;
    this.showZoneLabels = config.show_zone_labels !== false;
    this.autoTracking = config.auto_tracking === true;
  }

  getReportTargetsSwitchEntity() {
    const prefix = this.config.entity_prefix;
    const deviceName = prefix.replace(/^[^.]+\./, '');
    return `switch.${deviceName}_report_targets`;
  }

  toggleLiveView() {
    const switchEntity = this.getReportTargetsSwitchEntity();
    const switchState = this._hass.states[switchEntity];
    if (!switchState) return;
    const service = switchState.state === 'on' ? 'turn_off' : 'turn_on';
    this._hass.callService('switch', service, { entity_id: switchEntity });
  }

  async fetchMapConfig() {
    const deviceName = this.config.entity_prefix.replace(/^[^.]+\./, '');
    const service = `${deviceName}_get_map_config`;
    try {
      const response = await this._hass.callService('esphome', service, {}, undefined, undefined, true);
      this.mapConfig = response.response;
      this._doUpdate();
    } catch (e) {
      console.error(`[FP2 Card] Failed to fetch map config:`, e);
    }
  }

  // Resolve CSS variable to actual color for canvas (canvas can't use var())
  _resolveColor(varName, fallback) {
    if (!this._computedStyle) {
      this._computedStyle = getComputedStyle(this);
    }
    return this._computedStyle.getPropertyValue(varName).trim() || fallback;
  }

  initializeCard() {
    this.innerHTML = `
      <ha-card>
        <div class="fp2-header">
          <div class="fp2-title">${this.config.title || "Aqara FP2"}</div>
          <div class="fp2-controls">
            <button class="fp2-btn live-view-toggle" title="Toggle Live Tracking">
              <ha-icon icon="mdi:crosshairs-gps"></ha-icon>
            </button>
          </div>
        </div>
        <div class="fp2-content">
          <canvas id="fp2-canvas"></canvas>
        </div>
        <div class="fp2-info"></div>
      </ha-card>
      <style>
        ha-card {
          padding: 16px;
          overflow: hidden;
        }
        .fp2-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }
        .fp2-title {
          font-size: 18px;
          font-weight: 500;
          color: var(--primary-text-color);
        }
        .fp2-controls {
          display: flex;
          gap: 8px;
        }
        .fp2-btn {
          background: var(--secondary-background-color);
          border: 1px solid var(--divider-color);
          border-radius: 8px;
          padding: 6px 8px;
          cursor: pointer;
          color: var(--primary-text-color);
          transition: all 0.2s ease;
        }
        .fp2-btn:hover {
          background: var(--primary-color);
          color: var(--text-primary-color);
        }
        .fp2-btn.active {
          background: var(--primary-color);
          color: var(--text-primary-color);
          box-shadow: 0 0 8px rgba(var(--rgb-primary-color), 0.4);
        }
        .fp2-content {
          display: flex;
          flex-direction: column;
        }
        #fp2-canvas {
          width: 100%;
          max-height: 50vh;
          display: block;
          border-radius: 8px;
          box-sizing: border-box;
        }
        .fp2-info {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-top: 8px;
          font-size: 13px;
          color: var(--secondary-text-color);
        }
        .fp2-info .fp2-stat {
          display: flex;
          align-items: center;
          gap: 4px;
        }
        .fp2-info .fp2-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          display: inline-block;
        }
        .fp2-info .fp2-dot.presence { background: #4CAF50; }
        .fp2-info .fp2-dot.no-presence { background: #666; }
        .fp2-info .fp2-dot.target { background: #FF9800; }
        .fp2-info .fp2-dot.zone-on { background: #42A5F5; }
        .fp2-info .fp2-dot.zone-off { background: rgba(66,165,245,0.3); }
      </style>
    `;

    this.content = this.querySelector(".fp2-content");
    this.canvas = this.querySelector("#fp2-canvas");
    this.ctx = this.canvas.getContext("2d");
    this.infoPanel = this.querySelector(".fp2-info");

    this.querySelector(".live-view-toggle").addEventListener("click", () => this.toggleLiveView());
    this.canvas.addEventListener("click", (e) => this.handleCanvasClick(e));

    this.resizeObserver = new ResizeObserver(() => this._doUpdate());
    this.resizeObserver.observe(this.content);

    this.fetchMapConfig();

    // Auto-enable tracking when card loads
    if (this.autoTracking) {
      this._enableTracking();
    }
  }

  _enableTracking() {
    const switchEntity = this.getReportTargetsSwitchEntity();
    const switchState = this._hass && this._hass.states[switchEntity];
    if (switchState && switchState.state === 'off') {
      this._hass.callService('switch', 'turn_on', { entity_id: switchEntity });
      this._autoTrackingEnabled = true;
    }
  }

  _disableTracking() {
    if (!this._autoTrackingEnabled) return;
    const switchEntity = this.getReportTargetsSwitchEntity();
    const switchState = this._hass && this._hass.states[switchEntity];
    if (switchState && switchState.state === 'on') {
      this._hass.callService('switch', 'turn_off', { entity_id: switchEntity });
    }
    this._autoTrackingEnabled = false;
  }

  updateLiveViewButton() {
    const switchEntity = this.getReportTargetsSwitchEntity();
    const switchState = this._hass.states[switchEntity];
    const button = this.querySelector(".live-view-toggle");
    if (!button) return;
    button.classList.toggle('active', switchState && switchState.state === 'on');
  }

  gatherEntityData() {
    const prefix = this.config.entity_prefix;
    const hass = this._hass;
    const deviceName = prefix.replace(/^[^.]+\./, '');

    const getState = (entityId) => {
      const s = hass.states[entityId];
      return s ? s.state : null;
    };

    const decodeTargets = (base64String) => {
      if (!base64String || base64String === "" || base64String === "unknown") return [];
      try {
        const bin = atob(base64String);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        if (bytes.length < 1) return [];
        const count = bytes[0];
        const targets = [];
        const i16 = (o) => { const v = (bytes[o] << 8) | bytes[o+1]; return v > 32767 ? v - 65536 : v; };
        for (let i = 0; i < count; i++) {
          const o = 1 + (i * 14);
          if (o + 14 > bytes.length) break;
          targets.push({
            id: bytes[o], x: i16(o+1), y: i16(o+3), z: i16(o+5),
            velocity: i16(o+7), snr: i16(o+9),
            classifier: bytes[o+11], posture: bytes[o+12], active: bytes[o+13],
          });
        }
        return targets;
      } catch (e) { return []; }
    };

    const parseGrid = (gridString) => {
      if (!gridString || gridString.length !== 56) {
        return Array(14).fill(null).map(() => Array(14).fill(0));
      }
      const grid = [];
      for (let y = 0; y < 14; y++) {
        grid[y] = [];
        const rowBits = parseInt(gridString.substr(y * 4, 4), 16);
        for (let x = 0; x < 14; x++) grid[y][x] = (rowBits >> (13 - x)) & 1;
      }
      return grid;
    };

    const mapConfig = this.mapConfig || {};
    const zones = [];
    if (mapConfig.zones && Array.isArray(mapConfig.zones)) {
      mapConfig.zones.forEach((zc, i) => {
        let occupancy = false;
        if (zc.presence_sensor) {
          occupancy = getState(`binary_sensor.${zc.presence_sensor}`) === "on";
        }
        zones.push({
          id: zc.presence_sensor || `zone_${i}`,
          name: zc.name || (zc.presence_sensor || `Zone ${i+1}`).replace(/^.*_/, '').replace(/_/g, ' '),
          map: parseGrid(zc.grid),
          occupancy,
        });
      });
    }

    const targetsBase64 = getState(`${prefix}_targets`);
    const globalPresence = getState(`binary_sensor.${deviceName}_global_presence`);
    const totalPeople = getState(`${prefix}_total_people`);

    return {
      edgeLabelGrid: parseGrid(mapConfig.edge_grid),
      entryExitGrid: parseGrid(mapConfig.exit_grid),
      interferenceGrid: parseGrid(mapConfig.interference_grid),
      mountingPosition: mapConfig.mounting_position || "wall",
      zones,
      targets: decodeTargets(targetsBase64),
      globalPresence: globalPresence === "on",
      totalPeople: totalPeople ? parseFloat(totalPeople) : 0,
    };
  }

  renderCanvas(data) {
    const containerWidth = this.content.clientWidth;
    if (!containerWidth) return;

    // Invalidate cached computed style on resize
    this._computedStyle = null;

    const dpr = window.devicePixelRatio || 1;
    let minX = 0, maxX = 13, minY = 0, maxY = 13;

    if (this.displayMode === "zoomed") {
      let found = false;
      minX = 13; maxX = 0; minY = 13; maxY = 0;
      for (let y = 0; y < 14; y++) {
        for (let x = 0; x < 14; x++) {
          if (!data.edgeLabelGrid[y][x]) {
            found = true;
            minX = Math.min(minX, x); maxX = Math.max(maxX, x);
            minY = Math.min(minY, y); maxY = Math.max(maxY, y);
          }
        }
      }
      if (!found) { minX = 0; maxX = 13; minY = 0; maxY = 13; }
    }

    const gridWidth = maxX - minX + 1;
    const gridHeight = maxY - minY + 1;

    // Use the actual rendered size of the canvas (controlled by CSS aspect-ratio)
    const canvasRect = this.canvas.getBoundingClientRect();
    const canvasWidth = canvasRect.width;
    const canvasHeight = canvasRect.height;
    const cellSize = Math.min(canvasWidth / gridWidth, canvasHeight / gridHeight);

    this.canvas.width = canvasWidth * dpr;
    this.canvas.height = canvasHeight * dpr;
    this.ctx.scale(dpr, dpr);

    this.renderParams = { minX, maxX, minY, maxY, cellSize, canvasWidth, canvasHeight };

    // Background
    const bgColor = this._resolveColor('--card-background-color', '#1c1c1c');
    this.ctx.fillStyle = bgColor;
    this.ctx.fillRect(0, 0, canvasWidth, canvasHeight);

    // Draw layers
    this.drawBaseGrid(data, minX, maxX, minY, maxY, cellSize);
    this.drawEdgeLabels(data, minX, maxX, minY, maxY, cellSize);
    this.drawInterferenceSources(data, minX, maxX, minY, maxY, cellSize);
    this.drawEntryExitZones(data, minX, maxX, minY, maxY, cellSize);
    this.drawDetectionZones(data, minX, maxX, minY, maxY, cellSize);
    this.drawTargets(data, minX, maxX, minY, maxY, cellSize);
    if (this.showSensorPosition) {
      this.drawSensorPosition(data, minX, maxX, minY, maxY, cellSize);
    }
  }

  drawBaseGrid(data, minX, maxX, minY, maxY, cellSize) {
    if (!this.showGrid) return;
    this.ctx.strokeStyle = "rgba(255,255,255,0.06)";
    this.ctx.lineWidth = 0.5;
    for (let y = minY; y <= maxY + 1; y++) {
      const yPos = (y - minY) * cellSize;
      this.ctx.beginPath(); this.ctx.moveTo(0, yPos); this.ctx.lineTo((maxX - minX + 1) * cellSize, yPos); this.ctx.stroke();
    }
    for (let x = minX; x <= maxX + 1; x++) {
      const xPos = (x - minX) * cellSize;
      this.ctx.beginPath(); this.ctx.moveTo(xPos, 0); this.ctx.lineTo(xPos, (maxY - minY + 1) * cellSize); this.ctx.stroke();
    }
  }

  drawEdgeLabels(data, minX, maxX, minY, maxY, cellSize) {
    for (let y = minY; y <= maxY; y++) {
      for (let x = minX; x <= maxX; x++) {
        if (!data.edgeLabelGrid[y][x]) continue;
        const xPos = (x - minX) * cellSize;
        const yPos = (y - minY) * cellSize;
        // Subtle dark fill for out-of-bounds
        this.ctx.fillStyle = "rgba(0,0,0,0.3)";
        this.ctx.fillRect(xPos, yPos, cellSize, cellSize);
        // Diagonal hash
        this.ctx.strokeStyle = "rgba(255,255,255,0.05)";
        this.ctx.lineWidth = 0.5;
        this.ctx.beginPath();
        this.ctx.moveTo(xPos, yPos); this.ctx.lineTo(xPos + cellSize, yPos + cellSize);
        this.ctx.stroke();
      }
    }
  }

  drawInterferenceSources(data, minX, maxX, minY, maxY, cellSize) {
    for (let y = minY; y <= maxY; y++) {
      for (let x = minX; x <= maxX; x++) {
        if (!data.interferenceGrid[y][x]) continue;
        const xPos = (x - minX) * cellSize;
        const yPos = (y - minY) * cellSize;
        this.ctx.fillStyle = "rgba(244,67,54,0.25)";
        this.ctx.fillRect(xPos, yPos, cellSize, cellSize);
        // X pattern for interference
        this.ctx.strokeStyle = "rgba(244,67,54,0.4)";
        this.ctx.lineWidth = 1;
        this.ctx.beginPath();
        this.ctx.moveTo(xPos + 2, yPos + 2); this.ctx.lineTo(xPos + cellSize - 2, yPos + cellSize - 2);
        this.ctx.moveTo(xPos + cellSize - 2, yPos + 2); this.ctx.lineTo(xPos + 2, yPos + cellSize - 2);
        this.ctx.stroke();
      }
    }
  }

  drawEntryExitZones(data, minX, maxX, minY, maxY, cellSize) {
    for (let y = minY; y <= maxY; y++) {
      for (let x = minX; x <= maxX; x++) {
        if (!data.entryExitGrid[y][x]) continue;
        const xPos = (x - minX) * cellSize;
        const yPos = (y - minY) * cellSize;
        this.ctx.fillStyle = "rgba(76,175,80,0.15)";
        this.ctx.fillRect(xPos, yPos, cellSize, cellSize);
        this.ctx.strokeStyle = "rgba(76,175,80,0.5)";
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(xPos + 1, yPos + 1, cellSize - 2, cellSize - 2);
      }
    }
  }

  drawDetectionZones(data, minX, maxX, minY, maxY, cellSize) {
    data.zones.forEach((zone) => {
      const occupied = zone.occupancy;
      const fillColor = occupied ? "rgba(66,165,245,0.35)" : "rgba(66,165,245,0.08)";
      const borderColor = occupied ? "rgba(33,150,243,0.9)" : "rgba(33,150,243,0.25)";

      // Collect zone cells and find bounds
      let zMinX = 14, zMaxX = -1, zMinY = 14, zMaxY = -1;
      for (let y = 0; y < 14; y++) {
        for (let x = 0; x < 14; x++) {
          if (zone.map[y][x]) {
            zMinX = Math.min(zMinX, x); zMaxX = Math.max(zMaxX, x);
            zMinY = Math.min(zMinY, y); zMaxY = Math.max(zMaxY, y);
          }
        }
      }

      // Fill zone cells
      this.ctx.fillStyle = fillColor;
      for (let y = minY; y <= maxY; y++) {
        for (let x = minX; x <= maxX; x++) {
          if (zone.map[y][x]) {
            this.ctx.fillRect((x - minX) * cellSize, (y - minY) * cellSize, cellSize, cellSize);
          }
        }
      }

      // Draw clean outer border around the zone bounding box
      if (zMinX <= zMaxX && zMinX >= minX && zMaxX <= maxX && zMinY >= minY && zMaxY <= maxY) {
        const bx = (zMinX - minX) * cellSize;
        const by = (zMinY - minY) * cellSize;
        const bw = (zMaxX - zMinX + 1) * cellSize;
        const bh = (zMaxY - zMinY + 1) * cellSize;
        this.ctx.strokeStyle = borderColor;
        this.ctx.lineWidth = occupied ? 2.5 : 1.5;
        this.ctx.setLineDash(occupied ? [] : [4, 4]);
        this.ctx.strokeRect(bx + 1, by + 1, bw - 2, bh - 2);
        this.ctx.setLineDash([]);

        // Zone label
        if (this.showZoneLabels) {
          const cx = bx + bw / 2;
          const cy = by + bh / 2;
          const label = zone.name || zone.id;
          const fontSize = Math.min(cellSize * 0.5, 14);
          this.ctx.font = `600 ${fontSize}px system-ui, sans-serif`;
          this.ctx.textAlign = "center";
          this.ctx.textBaseline = "middle";
          const tw = this.ctx.measureText(label).width;
          const pad = 6;

          // Label background pill
          const rx = cx - tw / 2 - pad;
          const ry = cy - fontSize / 2 - pad / 2;
          const rw = tw + pad * 2;
          const rh = fontSize + pad;
          const r = rh / 2;
          this.ctx.fillStyle = occupied ? "rgba(33,150,243,0.85)" : "rgba(33,150,243,0.4)";
          this.ctx.beginPath();
          this.ctx.moveTo(rx + r, ry);
          this.ctx.lineTo(rx + rw - r, ry);
          this.ctx.arcTo(rx + rw, ry, rx + rw, ry + r, r);
          this.ctx.lineTo(rx + rw, ry + rh - r);
          this.ctx.arcTo(rx + rw, ry + rh, rx + rw - r, ry + rh, r);
          this.ctx.lineTo(rx + r, ry + rh);
          this.ctx.arcTo(rx, ry + rh, rx, ry + rh - r, r);
          this.ctx.lineTo(rx, ry + r);
          this.ctx.arcTo(rx, ry, rx + r, ry, r);
          this.ctx.closePath();
          this.ctx.fill();

          this.ctx.fillStyle = "#fff";
          this.ctx.fillText(label, cx, cy);
        }
      }
    });
  }

  drawTargets(data, minX, maxX, minY, maxY, cellSize) {
    if (!data.targets || !data.targets.length) return;

    const postureIcons = { 0: "\u{1F9CD}", 1: "\u{1F9CE}", 2: "\u{1F6CC}" }; // standing, kneeling, sleeping
    const postureLabels = { 0: "Standing", 1: "Sitting", 2: "Lying" };

    data.targets.forEach((target) => {
      const gridX = (-target.x + 400) / 800.0 * 14.0;
      const gridY = target.y / 800.0 * 14.0;
      if (gridX < minX || gridX > maxX + 1 || gridY < minY || gridY > maxY + 1) return;

      const xPos = (gridX - minX) * cellSize;
      const yPos = (gridY - minY) * cellSize;
      const radius = Math.min(cellSize * 0.35, 18);

      // Glow effect
      const gradient = this.ctx.createRadialGradient(xPos, yPos, 0, xPos, yPos, radius * 2.5);
      gradient.addColorStop(0, "rgba(255,152,0,0.3)");
      gradient.addColorStop(1, "rgba(255,152,0,0)");
      this.ctx.fillStyle = gradient;
      this.ctx.beginPath();
      this.ctx.arc(xPos, yPos, radius * 2.5, 0, Math.PI * 2);
      this.ctx.fill();

      // Target circle
      this.ctx.fillStyle = "rgba(255,152,0,0.9)";
      this.ctx.strokeStyle = "rgba(255,111,0,1)";
      this.ctx.lineWidth = 2;
      this.ctx.beginPath();
      this.ctx.arc(xPos, yPos, radius, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.stroke();

      // Posture icon or ID
      const fontSize = Math.min(cellSize * 0.45, 14);
      this.ctx.font = `bold ${fontSize}px system-ui, sans-serif`;
      this.ctx.textAlign = "center";
      this.ctx.textBaseline = "middle";
      this.ctx.fillStyle = "#000";

      const posture = target.posture;
      if (posture in postureLabels) {
        // Show posture initial: S(tanding), s(itting), L(ying)
        const initials = { 0: "S", 1: "s", 2: "L" };
        this.ctx.fillText(initials[posture] || target.id, xPos, yPos);
      } else {
        this.ctx.fillText(target.id, xPos, yPos);
      }

      // Velocity indicator (small arrow showing movement direction)
      if (Math.abs(target.velocity) > 5) {
        const speed = Math.min(Math.abs(target.velocity) / 100, 1);
        const arrowLen = radius * 1.5 * speed;
        const angle = target.velocity > 0 ? -Math.PI / 2 : Math.PI / 2; // towards/away from sensor
        this.ctx.strokeStyle = "rgba(255,255,255,0.7)";
        this.ctx.lineWidth = 2;
        this.ctx.beginPath();
        this.ctx.moveTo(xPos, yPos + radius + 2);
        this.ctx.lineTo(xPos, yPos + radius + 2 + arrowLen);
        this.ctx.stroke();
      }
    });
  }

  drawSensorPosition(data, minX, maxX, minY, maxY, cellSize) {
    let sensorX, sensorY;
    switch (data.mountingPosition) {
      case "left_upper_corner": case "left_corner": sensorX = 0; sensorY = 0; break;
      case "right_upper_corner": case "right_corner": sensorX = 14; sensorY = 0; break;
      case "wall": default: sensorX = 7; sensorY = 0; break;
    }
    if (sensorX < minX - 1 || sensorX > maxX + 1 || sensorY < minY - 1 || sensorY > maxY + 1) return;

    const xPos = (sensorX - minX) * cellSize;
    const yPos = (sensorY - minY) * cellSize;
    const size = cellSize * 0.3;

    // Radar wave arcs
    for (let i = 0; i < 3; i++) {
      this.ctx.strokeStyle = `rgba(244,67,54,${0.5 - i * 0.15})`;
      this.ctx.lineWidth = 1.5;
      this.ctx.beginPath();
      this.ctx.arc(xPos, yPos, size + i * 7, 0, Math.PI);
      this.ctx.stroke();
    }

    // Sensor dot
    this.ctx.fillStyle = "#f44336";
    this.ctx.beginPath();
    this.ctx.arc(xPos, yPos, 4, 0, Math.PI * 2);
    this.ctx.fill();

    // Label
    this.ctx.font = "bold 10px system-ui, sans-serif";
    this.ctx.fillStyle = "rgba(244,67,54,0.9)";
    this.ctx.textAlign = "center";
    this.ctx.textBaseline = "top";
    this.ctx.fillText("SENSOR", xPos, yPos + size + 22);
  }

  updateInfoPanel(data) {
    const activeZones = data.zones.filter(z => z.occupancy);
    const targetCount = data.targets ? data.targets.length : 0;
    const postureLabels = { 0: "Standing", 1: "Sitting", 2: "Lying" };

    let html = '';

    // Presence status
    const presClass = data.globalPresence ? "presence" : "no-presence";
    html += `<span class="fp2-stat"><span class="fp2-dot ${presClass}"></span>${data.globalPresence ? "Occupied" : "Clear"}</span>`;

    // People count
    if (data.totalPeople > 0) {
      html += `<span class="fp2-stat"><span class="fp2-dot target"></span>${data.totalPeople} ${data.totalPeople === 1 ? "person" : "people"}</span>`;
    }

    // Zone status
    data.zones.forEach(z => {
      const cls = z.occupancy ? "zone-on" : "zone-off";
      const name = z.name || z.id;
      html += `<span class="fp2-stat"><span class="fp2-dot ${cls}"></span>${name}</span>`;
    });

    // Target details
    if (targetCount > 0) {
      data.targets.forEach(t => {
        const posture = postureLabels[t.posture] || "?";
        html += `<span class="fp2-stat"><span class="fp2-dot target"></span>T${t.id}: ${posture}</span>`;
      });
    }

    this.infoPanel.innerHTML = html;
  }

  handleCanvasClick(e) {
    if (!this.renderParams) return;
    const rect = this.canvas.getBoundingClientRect();
    const { minX, minY, cellSize } = this.renderParams;
    const gridX = Math.floor((e.clientX - rect.left) / cellSize) + minX;
    const gridY = Math.floor((e.clientY - rect.top) / cellSize) + minY;
    // Could show cell details in a popup
  }

  disconnectedCallback() {
    if (this.resizeObserver) this.resizeObserver.disconnect();
    if (this._pendingUpdate) clearTimeout(this._pendingUpdate);
    if (this.autoTracking) this._disableTracking();
  }

  getCardSize() { return 8; }

  getGridOptions() {
    return { rows: "auto", columns: 6, min_rows: 4, max_rows: 12 };
  }
}

customElements.define("aqara-fp2-card", AqaraFP2Card);
window.customCards = window.customCards || [];
window.customCards.push({
  type: "aqara-fp2-card",
  name: "Aqara FP2 Presence Sensor Card",
  description: "Visualizes Aqara FP2 presence sensor data with zones and target tracking",
  preview: true,
});
