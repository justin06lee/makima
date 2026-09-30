// An app's icon, as the Finder draws it, saved as a 256px PNG.
//
//   osascript -l JavaScript app_icon.js /Applications/Foo.app /tmp/foo.png
//
// NSWorkspace rather than reading the bundle's .icns: newer apps keep their
// icon in an asset catalogue with no .icns at all, and this draws whichever
// the system itself would. Shared by the app (terminal.rs, include_str!) and
// the browser preview (vite.config.ts).
ObjC.import("AppKit");
function run(argv) {
  var size = 256;
  var img = $.NSWorkspace.sharedWorkspace.iconForFile(argv[0]);
  var rep = $.NSBitmapImageRep.alloc.initWithBitmapDataPlanesPixelsWidePixelsHighBitsPerSampleSamplesPerPixelHasAlphaIsPlanarColorSpaceNameBytesPerRowBitsPerPixel(
    null, size, size, 8, 4, true, false, $.NSDeviceRGBColorSpace, 0, 0);
  $.NSGraphicsContext.saveGraphicsState;
  $.NSGraphicsContext.setCurrentContext($.NSGraphicsContext.graphicsContextWithBitmapImageRep(rep));
  img.drawInRectFromRectOperationFraction($.NSMakeRect(0, 0, size, size), $.NSZeroRect, $.NSCompositingOperationCopy, 1.0);
  $.NSGraphicsContext.restoreGraphicsState;
  var png = rep.representationUsingTypeProperties($.NSBitmapImageFileTypePNG, $());
  return png.writeToFileAtomically(argv[1], true) ? "ok" : "failed";
}
