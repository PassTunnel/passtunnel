import CryptoKit
import Foundation

/// A secret encrypted to a profile's protection key (a Secure Enclave P-256 key-agreement key),
/// ECIES-style:
///
/// - a fresh ephemeral P-256 key per encryption, ECDH with the recipient (protection) public key;
/// - HKDF-SHA256 over the shared secret, salt = ephemeral public key ‖ recipient public key (both
///   X9.63), info = "PassTunnel secret v1", 32 bytes;
/// - AES-256-GCM with the Keychain account ("<profileID>/<kind>") as additional data, so an envelope
///   cannot be moved to another item or profile.
///
/// Stored text: `ptse1:` + Base64( version 0x01 ‖ ephemeral public key (65) ‖ nonce (12) ‖
/// ciphertext ‖ tag (16) ). Encrypting needs only the public key; opening needs the private key,
/// which the Secure Enclave uses only after the user confirms (Touch ID or the login password).
///
/// Plain values that start like a marker are stored with the `ptpl1:` prefix, so the two forms can
/// never be confused.
public enum SecretEnvelope {
    static let marker = "ptse1:"
    static let markerFamily = "ptse"
    static let plainEscape = "ptpl1:"
    static let version: UInt8 = 1
    static let info = Data("PassTunnel secret v1".utf8)
    static let publicKeyLength = 65
    static let nonceLength = 12
    static let tagLength = 16

    /// Text written by `seal` (any version, so newer ones are recognized and refused, not misread).
    public static func isEnvelope(_ text: String) -> Bool { text.hasPrefix(markerFamily) }

    static func encodePlain(_ value: String) -> String {
        value.hasPrefix(markerFamily) || value.hasPrefix("ptpl") ? plainEscape + value : value
    }

    static func decodePlain(_ text: String) -> String {
        text.hasPrefix(plainEscape) ? String(text.dropFirst(plainEscape.count)) : text
    }

    /// Encrypts `plaintext` to `recipient`. `account` is bound as additional authenticated data.
    public static func seal(_ plaintext: String, to recipient: P256.KeyAgreement.PublicKey, account: String) throws -> String {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let key = symmetricKey(shared, ephemeral: ephemeral.publicKey, recipient: recipient)
        let box = try AES.GCM.seal(Data(plaintext.utf8), using: key, authenticating: Data(account.utf8))
        var blob = Data([version])
        blob.append(ephemeral.publicKey.x963Representation)
        blob.append(contentsOf: box.nonce)
        blob.append(box.ciphertext)
        blob.append(box.tag)
        return marker + blob.base64EncodedString()
    }

    /// The parts of a stored envelope; nil when it is not one this version can read.
    struct Parsed {
        var ephemeral: P256.KeyAgreement.PublicKey
        var box: AES.GCM.SealedBox
    }

    static func parse(_ text: String) -> Parsed? {
        guard text.hasPrefix(marker), let blob = Data(base64Encoded: String(text.dropFirst(marker.count))),
              blob.count >= 1 + publicKeyLength + nonceLength + tagLength, blob.first == version else { return nil }
        let bytes = [UInt8](blob)
        var i = 1
        func take(_ n: Int) -> Data { defer { i += n }; return Data(bytes[i..<(i + n)]) }
        guard let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: take(publicKeyLength)),
              let nonce = try? AES.GCM.Nonce(data: take(nonceLength)) else { return nil }
        let ciphertext = take(bytes.count - i - tagLength)
        let tag = take(tagLength)
        guard let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else { return nil }
        return Parsed(ephemeral: ephemeral, box: box)
    }

    /// Decrypts with the shared secret the protection key computed for `parsed.ephemeral`.
    /// Throws `PTError.protectedSecretUnreadable` when the data was changed or belongs elsewhere.
    static func open(_ parsed: Parsed, shared: SharedSecret, recipient: P256.KeyAgreement.PublicKey,
                     account: String, kind: SecretKind) throws -> String {
        let key = symmetricKey(shared, ephemeral: parsed.ephemeral, recipient: recipient)
        guard let data = try? AES.GCM.open(parsed.box, using: key, authenticating: Data(account.utf8)),
              let text = String(data: data, encoding: .utf8) else {
            throw PTError.protectedSecretUnreadable(kind)
        }
        return text
    }

    private static func symmetricKey(_ shared: SharedSecret, ephemeral: P256.KeyAgreement.PublicKey,
                                     recipient: P256.KeyAgreement.PublicKey) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self,
                                       salt: ephemeral.x963Representation + recipient.x963Representation,
                                       sharedInfo: info, outputByteCount: 32)
    }
}

/// The Keychain record of a profile's protection key (account "<profileID>/sekey"): the private key
/// as the Secure Enclave's wrapped blob (`dataRepresentation`, useless on another Mac) and the public key.
struct ProtectionKeyRecord: Codable, Equatable {
    var v = 1
    var key: Data          // SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation
    var pub: Data          // X9.63 public key

    var publicKey: P256.KeyAgreement.PublicKey? { try? P256.KeyAgreement.PublicKey(x963Representation: pub) }

    func encoded() throws -> String {
        String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }

    static func decode(_ text: String) -> ProtectionKeyRecord? {
        guard let r = try? JSONDecoder().decode(ProtectionKeyRecord.self, from: Data(text.utf8)), r.v == 1 else { return nil }
        return r
    }
}
