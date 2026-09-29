// Draws the menu bar icon from the app icon, so the two are one picture:
// the ringed iris, lifted out of its tile as a template (black, with the
// shape in alpha) that macOS tints to suit the menu bar.
//
//   swift scripts/tray-icon.swift   (from desktop/, after changing the app icon)
//
// The painted rings are softened a little before they are cut out, so they
// keep their hand-drawn wobble at menu bar size without the speckle turning
// to grey mush. macOS only; the result is checked in.

import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
let here = URL(fileURLWithPath: #filePath, relativeTo: cwd).absoluteURL
let dir = here.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("src-tauri/icons")
let source = dir.appendingPathComponent("icon-source.png")
let output = dir.appendingPathComponent("tray.png")

/// Working size, and the size written: the tray draws it 18pt tall, so 72px
/// stays sharp on a Retina menu bar.
let N = 1024
let OUT = 72
/// Where the iris sits in the 1024px tile, and how far out to take it: far
/// enough for the ragged edge, short of the dark smudges in the tile's corners.
let centre = (x: 515.0, y: 520.0)
let reach = 352.0
/// Ink darker than `dark` is solid, lighter than `light` is gone.
let dark = 0.20
let light = 0.32
/// How much to soften the paint before cutting it out, in working pixels.
let soften = 7

guard let src = CGImageSourceCreateWithURL(source as CFURL, nil), let image = CGImageSourceCreateImageAtIndex(src, 0, nil) else {
  fatalError("can't read \(source.path)")
}

// The tile in grey, one byte a pixel.
var grey = [UInt8](repeating: 255, count: N * N)
grey.withUnsafeMutableBytes { buf in
  let ctx = CGContext(data: buf.baseAddress, width: N, height: N, bitsPerComponent: 8, bytesPerRow: N,
                      space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue)!
  ctx.setFillColor(gray: 1, alpha: 1)
  ctx.fill(CGRect(x: 0, y: 0, width: N, height: N))
  ctx.interpolationQuality = .high
  ctx.draw(image, in: CGRect(x: 0, y: 0, width: N, height: N))
}

// Soften: a box blur, across then down, run twice to round it off.
func blur(_ a: [Double], _ r: Int) -> [Double] {
  var t = [Double](repeating: 0, count: N * N)
  var o = [Double](repeating: 0, count: N * N)
  for y in 0..<N {
    var s = 0.0
    for x in -r...r { s += a[y * N + min(max(x, 0), N - 1)] }
    for x in 0..<N {
      t[y * N + x] = s / Double(2 * r + 1)
      s += a[y * N + min(x + r + 1, N - 1)] - a[y * N + max(x - r, 0)]
    }
  }
  for x in 0..<N {
    var s = 0.0
    for y in -r...r { s += t[min(max(y, 0), N - 1) * N + x] }
    for y in 0..<N {
      o[y * N + x] = s / Double(2 * r + 1)
      s += t[min(y + r + 1, N - 1) * N + x] - t[max(y - r, 0) * N + x]
    }
  }
  return o
}
var lum = grey.map { Double($0) / 255 }
lum = blur(blur(lum, soften), soften)

// Ink, inside the iris only; the bitmap's rows run top down.
var ink = [Double](repeating: 0, count: N * N)
for y in 0..<N {
  for x in 0..<N {
    let d = hypot(Double(x) - centre.x, Double(y) - centre.y)
    let edge = min(max((reach - d) / 24, 0), 1)
    let v = min(max((light - lum[y * N + x]) / (light - dark), 0), 1)
    ink[y * N + x] = v * edge
  }
}

// Frame it: the square round the iris, with a little room, shrunk by
// averaging so the edges stay smooth.
let side = Int(reach * 2 / 0.94)
let x0 = Int(centre.x) - side / 2
let y0 = Int(centre.y) - side / 2
var rgba = [UInt8](repeating: 0, count: OUT * OUT * 4)
for oy in 0..<OUT {
  for ox in 0..<OUT {
    let sx0 = x0 + ox * side / OUT, sx1 = x0 + (ox + 1) * side / OUT
    let sy0 = y0 + oy * side / OUT, sy1 = y0 + (oy + 1) * side / OUT
    var s = 0.0, n = 0.0
    for sy in sy0..<sy1 {
      for sx in sx0..<sx1 {
        n += 1
        if sx >= 0, sx < N, sy >= 0, sy < N { s += ink[sy * N + sx] }
      }
    }
    rgba[(oy * OUT + ox) * 4 + 3] = UInt8((s / max(n, 1) * 255).rounded())
  }
}

let data = CFDataCreate(nil, rgba, rgba.count)!
let out = CGImage(width: OUT, height: OUT, bitsPerComponent: 8, bitsPerPixel: 32, bytesPerRow: OUT * 4,
                  space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.last.rawValue),
                  provider: CGDataProvider(data: data)!, decode: nil, shouldInterpolate: true, intent: .defaultIntent)!
let dest = CGImageDestinationCreateWithURL(output as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(dest, out, nil)
guard CGImageDestinationFinalize(dest) else { fatalError("can't write \(output.path)") }
print("wrote \(output.path)")
