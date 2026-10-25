// macOS only, like QRDecoder (Vision).
#if os(macOS)
import CoreImage
import Foundation
import ImageIO
import UniformTypeIdentifiers
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

final class QRDecoderTests: XCTestCase {
    let uri = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme&digits=8&period=60&algorithm=SHA256"

    /// QR code rendered by CoreImage, scaled up so every module is several pixels wide.
    func makeQR(_ text: String, scale: CGFloat = 8) throws -> CGImage {
        let filter = try XCTUnwrap(CIFilter(name: "CIQRCodeGenerator"))
        filter.setValue(Data(text.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        let output = try XCTUnwrap(filter.outputImage).transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let context = CIContext(options: [.useSoftwareRenderer: true])
        return try XCTUnwrap(context.createCGImage(output, from: output.extent))
    }

    func png(_ image: CGImage) throws -> Data {
        let data = NSMutableData()
        let dest = try XCTUnwrap(CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil))
        CGImageDestinationAddImage(dest, image, nil)
        XCTAssertTrue(CGImageDestinationFinalize(dest))
        return data as Data
    }

    func testDecodesOTPAuthFromGeneratedQR() throws {
        let parsed = try QRDecoder.otpAuth(in: makeQR(uri))
        XCTAssertEqual(parsed.issuer, "Acme")
        XCTAssertEqual(parsed.account, "alice")
        XCTAssertEqual(parsed.secret, try TOTP.decodeSecret("JBSWY3DPEHPK3PXP"))
        XCTAssertEqual(parsed.params, TOTPParams(digits: 8, period: 60, algorithm: .sha256))
    }

    func testDecodesFromPNGDataAndFile() throws {
        let data = try png(makeQR(uri))
        XCTAssertEqual(try QRDecoder.payloads(inImageData: data), [uri])
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("qr-\(UUID().uuidString).png")
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        XCTAssertEqual(try QRDecoder.otpAuth(inFile: url).account, "alice")
    }

    func testNonOTPPayload() throws {
        XCTAssertThrowsError(try QRDecoder.otpAuth(in: makeQR("https://vpn.example.com"))) {
            XCTAssertEqual($0 as? QRDecoder.Failure, .notOTPAuth)
        }
        XCTAssertThrowsError(try QRDecoder.otpAuth(from: ["otpauth-migration://offline?data=AAAA"])) {
            XCTAssertEqual($0 as? QRDecoder.Failure, .migrationExport)
        }
        XCTAssertThrowsError(try QRDecoder.otpAuth(from: ["otpauth://hotp/Acme:alice?secret=JBSWY3DPEHPK3PXP"])) {
            XCTAssertEqual($0 as? PTError, .hotpNotSupported)
        }
    }

    func testImageWithoutCode() throws {
        let context = try XCTUnwrap(CGContext(data: nil, width: 64, height: 64, bitsPerComponent: 8, bytesPerRow: 0,
                                              space: CGColorSpaceCreateDeviceRGB(),
                                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        context.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: 64, height: 64))
        let blank = try XCTUnwrap(context.makeImage())
        XCTAssertThrowsError(try QRDecoder.payloads(in: blank)) {
            XCTAssertEqual($0 as? QRDecoder.Failure, .noCode)
        }
    }

    /// A white "screen" of `width` × `height` pixels with `qr` drawn at `origin` (like a browser page on a display).
    func screen(width: Int = 1600, height: Int = 1000, with qr: CGImage? = nil,
                at origin: CGPoint = CGPoint(x: 900, y: 300)) throws -> CGImage {
        let context = try XCTUnwrap(CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                                              space: CGColorSpaceCreateDeviceRGB(),
                                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        context.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        if let qr {
            // CIQRCodeGenerator leaves no quiet zone; the white screen around it is one.
            context.draw(qr, in: CGRect(origin: origin, size: CGSize(width: qr.width, height: qr.height)))
        }
        return try XCTUnwrap(context.makeImage())
    }

    func testFindsTheCodeOnAnyOfSeveralScreens() throws {
        let code = try makeQR(uri, scale: 5)
        // Scan QR on screen: one picture per display; the code is on the second.
        XCTAssertEqual(try QRDecoder.otpAuth(inAny: [screen(), screen(with: code)]).account, "alice")
        // Another QR code (a link) earlier on does not hide the authenticator's.
        let link = try makeQR("https://vpn.example.com", scale: 5)
        XCTAssertEqual(try QRDecoder.otpAuth(inAny: [screen(with: link, at: CGPoint(x: 100, y: 100)), screen(with: code)]).issuer,
                       "Acme")
        XCTAssertThrowsError(try QRDecoder.otpAuth(inAny: [screen(), screen()])) {
            XCTAssertEqual($0 as? QRDecoder.Failure, .noCode)
        }
        XCTAssertThrowsError(try QRDecoder.otpAuth(inAny: [])) {
            XCTAssertEqual($0 as? QRDecoder.Failure, .noCode)
        }
        XCTAssertThrowsError(try QRDecoder.otpAuth(inAny: [screen(with: link)])) {
            XCTAssertEqual($0 as? QRDecoder.Failure, .notOTPAuth)
        }
    }

    func testUnreadableData() {
        XCTAssertThrowsError(try QRDecoder.payloads(inImageData: Data("not an image".utf8))) {
            XCTAssertEqual($0 as? QRDecoder.Failure, .unreadableImage)
        }
    }
}
#endif
