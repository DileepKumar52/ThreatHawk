import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

console.log('🦅 ThreatHawk Favicon & Brand Asset Pipeline');
console.log('============================================');

// 1. Master Scalable SVG Vector (favicon.svg)
const masterSvg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <!-- Background Gradient -->
    <linearGradient id="th-bg" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#0a0f1d" />
      <stop offset="100%" stop-color="#03060b" />
    </linearGradient>

    <!-- Border Ring Gradient -->
    <linearGradient id="th-border" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.6" />
      <stop offset="50%" stop-color="#0070f3" stop-opacity="0.3" />
      <stop offset="100%" stop-color="#1e293b" stop-opacity="0.8" />
    </linearGradient>

    <!-- Radial Cyber Threat Glow -->
    <radialGradient id="th-glow" cx="50%" cy="45%" r="48%">
      <stop offset="0%" stop-color="#0070f3" stop-opacity="0.35" />
      <stop offset="60%" stop-color="#00dfd8" stop-opacity="0.10" />
      <stop offset="100%" stop-color="#0070f3" stop-opacity="0" />
    </radialGradient>

    <!-- Primary Wing Gradient (Left) -->
    <linearGradient id="th-wing-left" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38bdf8" />
      <stop offset="50%" stop-color="#0070f3" />
      <stop offset="100%" stop-color="#0751b3" />
    </linearGradient>

    <!-- Primary Wing Gradient (Right) -->
    <linearGradient id="th-wing-right" x1="100%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#60a5fa" />
      <stop offset="50%" stop-color="#0070f3" />
      <stop offset="100%" stop-color="#033d8c" />
    </linearGradient>

    <!-- Beak & Crown Crisp Silver/White -->
    <linearGradient id="th-beak" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ffffff" />
      <stop offset="100%" stop-color="#cbd5e1" />
    </linearGradient>

    <!-- Core Cyan Accent -->
    <linearGradient id="th-cyan" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#00dfd8" />
      <stop offset="100%" stop-color="#0070f3" />
    </linearGradient>
  </defs>

  <!-- Squircle Base -->
  <rect x="0" y="0" width="512" height="512" rx="112" fill="url(#th-bg)" />
  <rect x="2" y="2" width="508" height="508" rx="110" fill="none" stroke="url(#th-border)" stroke-width="4" />

  <!-- Background Ambience -->
  <circle cx="256" cy="245" r="170" fill="url(#th-glow)" />

  <!-- Shield & Hawk Graphics -->
  <g id="threatHawkEmblem">
    <!-- Outer Wing Blades (Upper Left & Right) -->
    <path d="M256 128 L170 88 L104 168 L176 220 L234 186 Z" fill="url(#th-wing-left)" opacity="0.95" />
    <path d="M256 128 L342 88 L408 168 L336 220 L278 186 Z" fill="url(#th-wing-right)" opacity="0.95" />

    <!-- Mid Wing Blades (Armor Segments) -->
    <path d="M172 228 L84 190 L108 284 L204 298 Z" fill="url(#th-wing-left)" />
    <path d="M340 228 L428 190 L404 284 L308 298 Z" fill="url(#th-wing-right)" />

    <!-- Lower Wing / Shield Taper Blades -->
    <path d="M198 306 L124 294 L160 380 L238 376 Z" fill="url(#th-wing-left)" opacity="0.88" />
    <path d="M314 306 L388 294 L352 380 L274 376 Z" fill="url(#th-wing-right)" opacity="0.88" />

    <!-- Lower Shield Apex Point -->
    <path d="M256 448 L198 376 L256 398 L314 376 Z" fill="url(#th-cyan)" />

    <!-- Inner Core Telemetry Chevron -->
    <path d="M256 272 L212 344 L256 372 L300 344 Z" fill="url(#th-cyan)" />

    <!-- Hawk Head Crest (Crisp White #ffffff) -->
    <path d="M256 100 L236 142 L256 156 L276 142 Z" fill="#ffffff" />
    
    <!-- Hawk Brow & Eye Sockets -->
    <path d="M256 156 L216 168 L236 196 L256 182 L276 196 L296 168 Z" fill="#e2e8f0" />

    <!-- Glowing Cyber Eyes (Dual Vigilant Angled Slits) -->
    <polygon points="214,174 240,183 234,191 210,183" fill="#00dfd8" />
    <polygon points="298,174 272,183 278,191 302,183" fill="#00dfd8" />

    <!-- Sharp Predatory Beak (White to Silver Centerpiece) -->
    <path d="M256 182 L234 216 L256 268 L278 216 Z" fill="url(#th-beak)" />
    <path d="M256 182 L256 268 L234 216 Z" fill="#000000" opacity="0.12" />
  </g>
</svg>
`;

const faviconSvgPath = path.join(rootDir, 'favicon.svg');
fs.writeFileSync(faviconSvgPath, masterSvg.trim(), 'utf8');
console.log('✓ Written: favicon.svg');

// 2. Generate PNGs via PowerShell System.Drawing (High quality vector rendering)
const psScript = `
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = "Stop"

function Create-ThreatHawkBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    
    $scale = $size / 512.0
    function S([float]$v) { return $v * $scale }
    function P([float]$x, [float]$y) { return New-Object System.Drawing.PointF (S $x), (S $y) }

    # 1. Background Squircle
    $radius = S 112
    $bgPath = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $radius * 2
    
    $bgPath.AddArc(0, 0, $d, $d, 180, 90)
    $bgPath.AddArc($size - $d, 0, $d, $d, 270, 90)
    $bgPath.AddArc($size - $d, $size - $d, $d, $d, 0, 90)
    $bgPath.AddArc(0, $size - $d, $d, $d, 90, 90)
    $bgPath.CloseFigure()
    
    $bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush (
        (New-Object System.Drawing.PointF 0, 0),
        (New-Object System.Drawing.PointF 0, $size),
        ([System.Drawing.Color]::FromArgb(255, 10, 15, 29)),
        ([System.Drawing.Color]::FromArgb(255, 3, 6, 11))
    )
    $g.FillPath($bgBrush, $bgPath)
    $bgBrush.Dispose()

    # Border Ring
    $borderPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(150, 56, 189, 248)), (S 3)
    $g.DrawPath($borderPen, $bgPath)
    $borderPen.Dispose()
    $bgPath.Dispose()

    # Ambient Glow
    if ($size -ge 32) {
        $glowPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        $glowPath.AddEllipse((S 128), (S 128), (S 256), (S 256))
        $pbg = New-Object System.Drawing.Drawing2D.PathGradientBrush $glowPath
        $pbg.CenterColor = [System.Drawing.Color]::FromArgb(90, 0, 112, 243)
        $pbg.SurroundColors = @([System.Drawing.Color]::FromArgb(0, 0, 112, 243))
        $g.FillPath($pbg, $glowPath)
        $pbg.Dispose()
        $glowPath.Dispose()
    }

    # Wings
    $wlBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush (
        (P 100 90), (P 256 380),
        ([System.Drawing.Color]::FromArgb(255, 56, 189, 248)),
        ([System.Drawing.Color]::FromArgb(255, 0, 112, 243))
    )
    $wrBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush (
        (P 412 90), (P 256 380),
        ([System.Drawing.Color]::FromArgb(255, 96, 165, 250)),
        ([System.Drawing.Color]::FromArgb(255, 2, 78, 187))
    )

    $g.FillPolygon($wlBrush, @( (P 256 128), (P 170 88), (P 104 168), (P 176 220), (P 234 186) ))
    $g.FillPolygon($wrBrush, @( (P 256 128), (P 342 88), (P 408 168), (P 336 220), (P 278 186) ))
    $g.FillPolygon($wlBrush, @( (P 172 228), (P 84 190), (P 108 284), (P 204 298) ))
    $g.FillPolygon($wrBrush, @( (P 340 228), (P 428 190), (P 404 284), (P 308 298) ))
    $g.FillPolygon($wlBrush, @( (P 198 306), (P 124 294), (P 160 380), (P 238 376) ))
    $g.FillPolygon($wrBrush, @( (P 314 306), (P 388 294), (P 352 380), (P 274 376) ))

    $wlBrush.Dispose()
    $wrBrush.Dispose()

    # Core & Shield Point
    $cyanBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush (
        (P 256 270), (P 256 450),
        ([System.Drawing.Color]::FromArgb(255, 0, 223, 216)),
        ([System.Drawing.Color]::FromArgb(255, 0, 112, 243))
    )
    $g.FillPolygon($cyanBrush, @( (P 256 448), (P 198 376), (P 256 398), (P 314 376) ))
    $g.FillPolygon($cyanBrush, @( (P 256 272), (P 212 344), (P 256 372), (P 300 344) ))
    $cyanBrush.Dispose()

    # Head Crest
    $whiteBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
    $g.FillPolygon($whiteBrush, @( (P 256 100), (P 236 142), (P 256 156), (P 276 142) ))

    # Brow
    $silverBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 226, 232, 240))
    $g.FillPolygon($silverBrush, @( (P 256 156), (P 216 168), (P 236 196), (P 256 182), (P 276 196), (P 296 168) ))
    $silverBrush.Dispose()

    # Glowing Cyber Eyes
    $eyeBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 0, 223, 216))
    $g.FillPolygon($eyeBrush, @( (P 214 174), (P 240 183), (P 234 191), (P 210 183) ))
    $g.FillPolygon($eyeBrush, @( (P 298 174), (P 272 183), (P 278 191), (P 302 183) ))
    $eyeBrush.Dispose()

    # Predatory Beak
    $beakLBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 226, 232, 240))
    $g.FillPolygon($beakLBrush, @( (P 256 182), (P 234 216), (P 256 268) ))
    $beakLBrush.Dispose()
    $g.FillPolygon($whiteBrush, @( (P 256 182), (P 278 216), (P 256 268) ))
    $whiteBrush.Dispose()

    $g.Dispose()
    return $bmp
}

$sizes = @(16, 32, 48, 96, 180, 192, 512)
foreach ($s in $sizes) {
    $bmp = Create-ThreatHawkBitmap $s
    $bmp.Save("scripts/tmp-icon-$s.png", [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}
`;

const tmpPsScript = path.join(rootDir, 'scripts/tmp-render.ps1');
fs.writeFileSync(tmpPsScript, psScript, 'utf8');

execSync(`powershell -ExecutionPolicy Bypass -File "${tmpPsScript}"`, { stdio: 'inherit' });
fs.unlinkSync(tmpPsScript);

// Copy designated sizes to destination files
const copyPlan = [
    { src: 'scripts/tmp-icon-96.png', dest: 'favicon-96x96.png' },
    { src: 'scripts/tmp-icon-180.png', dest: 'apple-touch-icon.png' },
    { src: 'scripts/tmp-icon-192.png', dest: 'web-app-manifest-192x192.png' },
    { src: 'scripts/tmp-icon-512.png', dest: 'web-app-manifest-512x512.png' }
];

for (const item of copyPlan) {
    fs.copyFileSync(path.join(rootDir, item.src), path.join(rootDir, item.dest));
    console.log(`✓ Generated: ${item.dest} (${fs.statSync(path.join(rootDir, item.dest)).size} bytes)`);
}

// 3. Assemble Multi-Resolution ICO File (16, 32, 48)
function assembleIco(pngBuffers) {
    const count = pngBuffers.length;
    const header = Buffer.alloc(6);
    header.writeUInt16LE(0, 0); // reserved
    header.writeUInt16LE(1, 2); // 1 = ICO
    header.writeUInt16LE(count, 4); // image count

    const dirEntries = [];
    let dataOffset = 6 + count * 16;

    for (const buf of pngBuffers) {
        const width = buf.readUInt32BE(16);
        const height = buf.readUInt32BE(20);

        const entry = Buffer.alloc(16);
        entry.writeUInt8(width >= 256 ? 0 : width, 0);
        entry.writeUInt8(height >= 256 ? 0 : height, 1);
        entry.writeUInt8(0, 2); // no palette
        entry.writeUInt8(0, 3); // reserved
        entry.writeUInt16LE(1, 4); // color planes
        entry.writeUInt16LE(32, 6); // 32 bpp
        entry.writeUInt32LE(buf.length, 8); // image size
        entry.writeUInt32LE(dataOffset, 12); // offset

        dirEntries.push(entry);
        dataOffset += buf.length;
    }

    return Buffer.concat([header, ...dirEntries, ...pngBuffers]);
}

const ico16 = fs.readFileSync(path.join(rootDir, 'scripts/tmp-icon-16.png'));
const ico32 = fs.readFileSync(path.join(rootDir, 'scripts/tmp-icon-32.png'));
const ico48 = fs.readFileSync(path.join(rootDir, 'scripts/tmp-icon-48.png'));

const finalIcoBuffer = assembleIco([ico16, ico32, ico48]);
const icoDest = path.join(rootDir, 'favicon.ico');
fs.writeFileSync(icoDest, finalIcoBuffer);
console.log(`✓ Generated: favicon.ico (${finalIcoBuffer.length} bytes, 16x16 + 32x32 + 48x48)`);

// Clean up temporary PNGs
for (const s of [16, 32, 48, 96, 180, 192, 512]) {
    const f = path.join(rootDir, `scripts/tmp-icon-${s}.png`);
    if (fs.existsSync(f)) fs.unlinkSync(f);
}

// Clean up preview directory
const prevDir = path.join(rootDir, 'scripts/favicon-preview');
if (fs.existsSync(prevDir)) fs.rmSync(prevDir, { recursive: true, force: true });

console.log('\n============================================');
console.log('ThreatHawk Favicons successfully modernized!');

