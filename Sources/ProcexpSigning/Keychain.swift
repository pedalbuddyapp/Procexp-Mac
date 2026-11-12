//
//  Keychain.swift
//  ProcexpSigning — W7
//
//  Minimal generic-password Keychain helper used to store the VirusTotal API
//  key. The key never lives in source or plists; users configure it once via
//  `CodeSignProvider.setAPIKey(_:)` and it is read back on demand.
//

import CryptoKit
import Foundation
import Security
import ProcexpModel

/// Namespaced Keychain access for the VirusTotal API key.
///
/// Stateless (an empty `enum`), so it is trivially `Sendable`. The underlying
/// `SecItem*` calls are thread-safe, so this can be used from any actor.
enum Keychain {
    /// Generic-password service name, as specified by the W7 contract.
    static let service = "com.sysinternals.procexpmac.virustotal"
    /// Single account under the service — we only ever store one API key.
    static let account = "api-key"

    /// Reads the stored API key; only absent or empty values are unconfigured.
    static func readAPIKey() throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw failure("read", status: status) }
        guard let data = item as? Data, let key = String(data: data, encoding: .utf8) else {
            throw ProviderError.underlying("Keychain API key is not valid UTF-8 data.")
        }
        return key.isEmpty ? nil : key
    }

    /// Stores (or replaces) the API key. Throws `ProviderError.underlying` on
    /// any Keychain failure so callers get a descriptive message.
    static func setAPIKey(_ key: String) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let value = [kSecValueData as String: Data(key.utf8)]
        var status = SecItemUpdate(base as CFDictionary, value as CFDictionary)
        if status == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = value[kSecValueData as String]
            status = SecItemAdd(add as CFDictionary, nil)
            // Another writer may have inserted the item after our update.
            if status == errSecDuplicateItem {
                status = SecItemUpdate(base as CFDictionary, value as CFDictionary)
            }
        }
        guard status == errSecSuccess else {
            throw failure("write", status: status)
        }
    }

    /// Service/account for the cache-integrity key. Separate from the API key so
    /// the on-disk reputation cache can be authenticated even when no API key is
    /// configured.
    static let cacheKeyService = "com.sysinternals.procexpmac.virustotal.cache-integrity"
    static let cacheKeyAccount = "hmac-key"

    /// Returns the key that authenticates the on-disk reputation cache, creating
    /// it on first use. The Keychain ACL keeps other processes of the same user
    /// from reading it, so a forged cache file fails verification.
    static func cacheIntegrityKey() throws -> SymmetricKey {
        if let existing = try readCacheIntegrityKey() { return existing }
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw failure("generate", status: status) }
        let key = SymmetricKey(data: Data(bytes))
        try storeCacheIntegrityKey(key)
        return key
    }

    private static func readCacheIntegrityKey() throws -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: cacheKeyService,
            kSecAttrAccount as String: cacheKeyAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw failure("read", status: status) }
        guard let data = item as? Data, data.count == 32 else {
            throw ProviderError.underlying("Keychain cache-integrity key is not 32 bytes.")
        }
        return SymmetricKey(data: data)
    }

    private static func storeCacheIntegrityKey(_ key: SymmetricKey) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: cacheKeyService,
            kSecAttrAccount as String: cacheKeyAccount,
        ]

        let value = [kSecValueData as String: key.withUnsafeBytes { Data($0) }]
        var status = SecItemUpdate(base as CFDictionary, value as CFDictionary)
        if status == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = value[kSecValueData as String]
            status = SecItemAdd(add as CFDictionary, nil)
            if status == errSecDuplicateItem {
                status = SecItemUpdate(base as CFDictionary, value as CFDictionary)
            }
        }
        guard status == errSecSuccess else {
            throw failure("write", status: status)
        }
    }

    private static func failure(_ operation: String, status: OSStatus) -> ProviderError {
        let detail = SecCopyErrorMessageString(status, nil) as String? ?? "Security.framework error"
        return .underlying("Keychain \(operation) failed (OSStatus \(status)): \(detail)")
    }
}
