import CryptoKit
import Foundation
import LocalAuthentication
import Security

private struct ProtectedKey: Codable {
    let device: String
    let key: Data
    let peer: Data
    let sealed: Data
}

private struct Request: Decodable {
    let operation: String
    let context: Data
    let secret: Data?
    let protectedKey: Data?
    let reason: String
}

private struct Reply: Encodable {
    var data: Data?
    var error: String?
}

/// Returns the hardware identifier used to associate keys with this device.
private func deviceID() throws -> String {
    var id: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    var timeout = timespec(tv_sec: 5, tv_nsec: 0)
    guard gethostuuid(&id, &timeout) == 0 else {
        throw NSError(domain: "Factr", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot identify this Mac"])
    }
    return UUID(uuid: id).uuidString
}

/// Creates an authentication context without reusing a previous Touch ID check.
private func authentication(_ reason: String) -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return context
}

/// Decrypts a protected secret using an authenticated Secure Enclave operation.
private func open(_ protected: ProtectedKey, context: Data, reason: String) throws -> Data {
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: protected.key,
        authenticationContext: authentication(reason)
    )
    let peer = try P256.KeyAgreement.PublicKey(x963Representation: protected.peer)
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    let wrappingKey = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: context,
        sharedInfo: Data("Factr system protection v1".utf8), outputByteCount: 32
    )
    return try AES.GCM.open(AES.GCM.SealedBox(combined: protected.sealed), using: wrappingKey, authenticating: context)
}

// The opaque Secure Enclave key representation is stored in the vault, not in
// the entitlement-gated data protection keychain. Private operations still
// require user presence enforced by the system access control.
/// Dispatches availability, protection, and unlock requests.
private func execute(_ request: Request) throws -> Data {
    switch request.operation {
    case "available":
        var error: NSError?
        guard SecureEnclave.isAvailable,
              LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw error ?? NSError(domain: "Factr", code: 2, userInfo: [NSLocalizedDescriptionKey: "Secure Enclave authentication is unavailable"])
        }
        return Data(try deviceID().utf8)
    case "protect":
        guard let secret = request.secret else { throw CocoaError(.coderValueNotFound) }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence], &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: access, authenticationContext: authentication(request.reason)
        )
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: key.publicKey)
        let wrappingKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: request.context,
            sharedInfo: Data("Factr system protection v1".utf8), outputByteCount: 32
        )
        let sealed = try AES.GCM.seal(secret, using: wrappingKey, authenticating: request.context)
        let protected = ProtectedKey(
            device: try deviceID(), key: key.dataRepresentation,
            peer: ephemeral.publicKey.x963Representation, sealed: sealed.combined!
        )
        // Verify that this installation can perform the protected operation
        // before offering to replace an existing vault.
        guard try open(protected, context: request.context, reason: request.reason) == secret else {
            throw CocoaError(.coderReadCorrupt)
        }
        return try JSONEncoder().encode(protected)
    case "unlock":
        let protected = try JSONDecoder().decode(ProtectedKey.self, from: request.protectedKey ?? Data())
        guard protected.device == (try deviceID()) else { throw CocoaError(.fileReadNoPermission) }
        return try open(protected, context: request.context, reason: request.reason)
    default:
        throw CocoaError(.coderInvalidValue)
    }
}

/// Handles a JSON request and returns an allocated JSON reply.
@_cdecl("factr_system_protection")
public func factrSystemProtection(_ bytes: UnsafePointer<UInt8>, _ count: Int) -> UnsafeMutablePointer<CChar>? {
    autoreleasepool {
        let reply: Reply
        do {
            let request = try JSONDecoder().decode(Request.self, from: Data(bytes: bytes, count: count))
            reply = Reply(data: try execute(request))
        } catch {
            reply = Reply(error: error.localizedDescription)
        }
        guard let data = try? JSONEncoder().encode(reply), let string = String(data: data, encoding: .utf8) else { return nil }
        return strdup(string)
    }
}

/// Wipes and releases a reply allocated by the native bridge.
@_cdecl("factr_system_protection_free")
public func factrSystemProtectionFree(_ pointer: UnsafeMutablePointer<CChar>) {
    // Replies may contain a plaintext vault key.
    memset_s(pointer, strlen(pointer), 0, strlen(pointer))
    free(pointer)
}
