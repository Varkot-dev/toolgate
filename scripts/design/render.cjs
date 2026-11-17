// Render a figure page to PNG files with headless Chromium (Node Playwright).
//
// Called by scripts/design/render.py with one argument: a JSON job file
//   { "html": "/abs/page.html", "width": 800,
//     "shots": [ { "t": 8.0 | null, "path": "/abs/out.png", "scale": 2, "square": false }, ... ] }
//
// The page must define window.figure = { init(): Promise, frame(t) }.
// init() lays the page out once fonts are in; frame(t) poses it at time t.
// CSS transitions and animations are off (system.css), so every capture is
// a pure function of t: same page, same t, same pixels.
const fs = require("fs");
const { chromium } = require("playwright");

(async () => {
  const job = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const browser = await chromium.launch({
    args: [
      "--font-render-hinting=none", "--force-color-profile=srgb", "--disable-lcd-text",
      // software raster on one thread, whole tiles: a pose renders the same pixels
      // whatever was on screen before it
      "--disable-gpu", "--disable-partial-raster", "--num-raster-threads=1",
      ...(process.env.FIG_CHROME_ARGS ? process.env.FIG_CHROME_ARGS.split(" ") : []),
    ],
  });
  const errors = [];
  const groups = new Map();
  for (const shot of job.shots) {
    const key = `${shot.scale}|${shot.square ? 1 : 0}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(shot);
  }
  for (const shots of groups.values()) {
    const { scale, square } = shots[0];
    const context = await browser.newContext({
      viewport: { width: job.width, height: 600 },
      deviceScaleFactor: scale,
      reducedMotion: "reduce",
    });
    const page = await context.newPage();
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    page.on("pageerror", (e) => errors.push(String(e)));
    await page.goto("file://" + job.html);
    const info = await page.evaluate(async (sq) => {
      if (sq) document.documentElement.classList.add("square");
      const faces = ["500 16px Jakarta", "700 18px Jakarta", "800 30px Jakarta", "500 16px Mono"];
      await Promise.all(faces.map((f) => document.fonts.load(f)));
      const missing = faces.filter((f) => !document.fonts.check(f));
      await window.figure.init();
      await document.fonts.ready;
      // Snap every icon to whole device pixels. Chromium can reuse one rasterized
      // icon for another copy of it, so copies at different sub-pixel offsets
      // would make the output depend on which one was drawn first.
      const dpr = window.devicePixelRatio;
      for (const svg of document.querySelectorAll(".stage svg:not(.wires)")) {
        const r = svg.getBoundingClientRect();
        const dx = Math.round(r.left * dpr) / dpr - r.left;
        const dy = Math.round(r.top * dpr) / dpr - r.top;
        svg.style.transform = `translate(${dx}px, ${dy}px)`;
      }
      const stage = document.querySelector(".stage");
      const height = Math.ceil(stage.getBoundingClientRect().height);
      stage.style.height = height + "px";
      return { height, missing, problems: window.figure.problems ? window.figure.problems() : [] };
    }, !!square);
    if (info.missing.length) errors.push("fonts not loaded: " + info.missing.join(", "));
    errors.push(...info.problems);
    await page.setViewportSize({ width: job.width, height: info.height });
    for (const shot of shots) {
      await page.evaluate((t) => {
        window.figure.frame(t);
        // Rebuild the render tree so no layer or raster state carries over from
        // the previous pose: each capture depends on t alone.
        const stage = document.querySelector(".stage");
        stage.style.display = "none";
        void stage.offsetHeight;
        stage.style.display = "";
        void stage.offsetHeight;
      }, shot.t);
      await page.screenshot({
        path: shot.path,
        clip: { x: 0, y: 0, width: job.width, height: info.height },
        omitBackground: true,
        animations: "disabled",
      });
    }
    await context.close();
  }
  await browser.close();
  if (errors.length) {
    console.error(errors.join("\n"));
    process.exit(2);
  }
})().catch((e) => { console.error(e); process.exit(1); });
