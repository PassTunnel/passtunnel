import Foundation
import PassTunnelVPNConfig

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto  // swift-crypto: the same API, outside Apple platforms
#endif

/// openconnect's `pin-sha256:` of a server certificate (docs/ARCHITECTURE.md, "Server trust"): the SHA-256 of the
/// complete DER of the certificate's SubjectPublicKeyInfo, in base64, which is what a Cisco AnyConnect profile's
/// `server_cert` holds (`OpenConnectPin`). Not `TLSFingerprint`'s hash of the whole certificate (FortiGate's
/// `trusted_cert`): a renewed certificate with the same key keeps this pin.
///
/// The SubjectPublicKeyInfo is found by a small, strict walk of the certificate's DER (RFC 5280, 4.1): the
/// Certificate SEQUENCE, its tbsCertificate SEQUENCE, the optional `[0]` version, then the serial number, the
/// signature algorithm, the issuer, the validity and the subject, and the SEQUENCE that follows them. Only
/// definite, minimally encoded lengths that stay inside their parent are read; anything else is nil.
public enum ServerKeyPin {
    /// The pin of the DER-encoded certificate `der` (`SecCertificateCopyData`), or nil when it is not one.
    public static func pin(certificate der: Data) -> String? {
        subjectPublicKeyInfo(certificate: der).map(pin(subjectPublicKeyInfo:))
    }

    /// `pin-sha256:` and the base64 of the SHA-256 of `spki` (the element's complete DER, tag and length included).
    public static func pin(subjectPublicKeyInfo spki: Data) -> String {
        OpenConnectPin.prefix + Data(SHA256.hash(data: spki)).base64EncodedString()
    }

    /// The complete DER of the certificate's SubjectPublicKeyInfo element; nil when `der` is not exactly one
    /// certificate as RFC 5280 lays it out.
    public static func subjectPublicKeyInfo(certificate der: Data) -> Data? {
        let bytes = [UInt8](der)
        var outer = DERReader(bytes, bytes.startIndex..<bytes.endIndex)
        // The certificate and nothing after it.
        guard let certificate = outer.next(), certificate.tag == DERReader.sequence, outer.isAtEnd else { return nil }
        var fields = DERReader(bytes, certificate.content)
        guard let tbs = fields.next(), tbs.tag == DERReader.sequence else { return nil }
        var tbsFields = DERReader(bytes, tbs.content)
        guard var element = tbsFields.next() else { return nil }
        // version [0] EXPLICIT, absent in a version 1 certificate.
        if element.tag == DERReader.versionTag {
            guard let next = tbsFields.next() else { return nil }
            element = next
        }
        // serialNumber, signature, issuer, validity, subject.
        guard element.tag == DERReader.integer else { return nil }
        for _ in 0..<4 {
            guard let next = tbsFields.next(), next.tag == DERReader.sequence else { return nil }
        }
        guard let spki = tbsFields.next(), spki.tag == DERReader.sequence else { return nil }
        // AlgorithmIdentifier and the key's BIT STRING, nothing else.
        var keyFields = DERReader(bytes, spki.content)
        guard let algorithm = keyFields.next(), algorithm.tag == DERReader.sequence,
            let key = keyFields.next(), key.tag == DERReader.bitString, !key.content.isEmpty, keyFields.isAtEnd
        else { return nil }
        return Data(bytes[spki.element])
    }
}

/// Reads the DER elements inside one range of `bytes`, one after the other.
struct DERReader {
    static let sequence: UInt8 = 0x30
    static let integer: UInt8 = 0x02
    static let bitString: UInt8 = 0x03
    /// `[0]` constructed: the certificate's version.
    static let versionTag: UInt8 = 0xA0

    struct Element {
        var tag: UInt8
        /// Tag, length and content.
        var element: Range<Int>
        var content: Range<Int>
    }

    private let bytes: [UInt8]
    private var index: Int
    private let end: Int

    init(_ bytes: [UInt8], _ range: Range<Int>) {
        self.bytes = bytes
        index = range.lowerBound
        end = range.upperBound
    }

    var isAtEnd: Bool { index == end }

    /// The next element, or nil (and no more) when it is not one: a multi-byte tag, an indefinite or
    /// non-minimal length, a length of more than four bytes, or one that runs past the range.
    mutating func next() -> Element? {
        let start = index
        guard end - start >= 2 else { return nil }
        let tag = bytes[start]
        guard tag & 0x1F != 0x1F else { return nil }
        var i = start + 1
        let first = bytes[i]
        i += 1
        var length = 0
        if first < 0x80 {
            length = Int(first)
        } else {
            let count = Int(first & 0x7F)
            // 0 is the indefinite length, which DER does not allow.
            guard (1...4).contains(count), end - i >= count, bytes[i] != 0 else { return nil }
            for k in 0..<count { length = length << 8 | Int(bytes[i + k]) }
            guard length >= 0x80 else { return nil }
            i += count
        }
        guard length <= end - i else {
            index = end
            return nil
        }
        index = i + length
        return Element(tag: tag, element: start..<index, content: i..<index)
    }
}
