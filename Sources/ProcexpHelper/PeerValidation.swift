//
//  PeerValidation.swift
//  ProcexpHelper — W2 (privileged root daemon)
//
//  Verify the code-signing identity of a connecting XPC peer before serving it.
//  A root daemon that hands out `task_for_pid`-level data must not answer just
//  any client, so each new connection is validated here.
//
//  Debug builds accept any peer with an intact signature so local ad-hoc
//  development remains possible. Release builds additionally require the
//  official app identifier and Microsoft Developer ID Team ID.
//

import Foundation
import ProcexpPrivileged
import Security
import os

enum PeerValidation {

    private static let officialAppIdentifier = HelperConstants.officialAppBundleID

    /// App identifier a connecting client must carry for this helper's flavor.
    private static var expectedAppIdentifier: String {
        HelperConstants.machServiceName == HelperConstants.developmentHelperBundleID
            ? HelperConstants.developmentAppBundleID
            : HelperConstants.officialAppBundleID
    }

    private static let log = Logger(
        subsystem: HelperConstants.machServiceName,
        category: "peer"
    )

    /// Decide whether to accept `connection`. Returns `true` to serve it.
    static func isTrusted(_ connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier

        // Resolve the peer's dynamic code object from its pid. (Audit-token
        // pinning via `kSecGuestAttributeAudit` is the hardened form and a W13
        // item; pid keying is used here because the audit_token_t accessor on
        // NSXPCConnection is SPI.)
        var code: SecCode?
        let attributes: [CFString: Any] = [kSecGuestAttributePid: pid]
        let copyStatus = SecCodeCopyGuestWithAttributes(
            nil, attributes as CFDictionary, SecCSFlags(rawValue: 0), &code
        )
        guard copyStatus == errSecSuccess, let code else {
            log.error("peer pid \(pid): SecCodeCopyGuestWithAttributes failed (\(copyStatus)); rejected")
            return false
        }

        // Validate the peer's signature is intact.
        let checkStatus = SecCodeCheckValidity(code, SecCSFlags(rawValue: 0), nil)
        if checkStatus != errSecSuccess {
            log.error("peer pid \(pid): SecCodeCheckValidity failed (\(checkStatus)); rejected")
            return false
        }

        #if DEBUG
        // Debug builds accept a self-signed development identity, but they must
        // still reject arbitrary local processes: the peer has to be signed by
        // the same certificate as this helper and carry the app's identifier,
        // because a self-signed identity has no Team ID to compare.
        var ownCode: SecCode?
        guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &ownCode) == errSecSuccess,
              let ownInformation = signingInformation(of: ownCode),
              let ownCertificates = ownInformation[kSecCodeInfoCertificates] as? [SecCertificate],
              let ownLeaf = ownCertificates.first,
              let peerInformation = signingInformation(of: code),
              let peerIdentifier = peerInformation[kSecCodeInfoIdentifier] as? String,
              peerIdentifier == expectedAppIdentifier,
              let peerCertificates = peerInformation[kSecCodeInfoCertificates] as? [SecCertificate],
              let peerLeaf = peerCertificates.first
        else {
            log.error("peer pid \(pid): missing a development identity matching \(expectedAppIdentifier); rejected")
            return false
        }
        guard (SecCertificateCopyData(peerLeaf) as Data) == (SecCertificateCopyData(ownLeaf) as Data) else {
            log.error("peer pid \(pid): signed by a different certificate than this helper; rejected")
            return false
        }

        log.notice("peer pid \(pid): development identity verified in DEBUG build; accepted")
        return true
        #else
        guard let teamIdentifier = ownTeamIdentifier() else {
            log.fault("could not determine helper Team ID; rejecting pid \(pid)")
            return false
        }

        let requirementText = "anchor apple generic and identifier \"\(officialAppIdentifier)\" and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
        var requirement: SecRequirement?
        let requirementStatus = SecRequirementCreateWithString(
            requirementText as CFString,
            SecCSFlags(rawValue: 0),
            &requirement
        )
        guard requirementStatus == errSecSuccess, let requirement else {
            log.fault("could not create official peer requirement (\(requirementStatus)); rejecting pid \(pid)")
            return false
        }

        let identityStatus = SecCodeCheckValidity(
            code,
            SecCSFlags(rawValue: 0),
            requirement
        )
        guard identityStatus == errSecSuccess else {
            log.error("peer pid \(pid): official identity requirement failed (\(identityStatus)); rejected")
            return false
        }

        log.info("peer pid \(pid): official identity requirement passed; accepted")
        return true
        #endif
    }

    /// Return the Team ID from this helper's own code signature. The app must
    /// be signed by the same team, avoiding a duplicated identity constant.
    private static func ownTeamIdentifier() -> String? {
        var ownCode: SecCode?
        guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &ownCode) == errSecSuccess,
              let ownCode else {
            return nil
        }

        var ownStaticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(
            ownCode,
            SecCSFlags(rawValue: 0),
            &ownStaticCode
        ) == errSecSuccess,
              let ownStaticCode else {
            return nil
        }

        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            ownStaticCode,
            SecCSFlags(rawValue: 0),
            &signingInformation
        ) == errSecSuccess,
              let information = signingInformation as? [CFString: Any] else {
            return nil
        }

        return information[kSecCodeInfoTeamIdentifier] as? String
    }

    /// Signing information (identifier and certificates) for `code`.
    private static func signingInformation(of code: SecCode?) -> [CFString: Any]? {
        guard let code else { return nil }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(
            code,
            SecCSFlags(rawValue: 0),
            &staticCode
        ) == errSecSuccess,
              let staticCode else {
            return nil
        }

        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: 0),
            &information
        ) == errSecSuccess else {
            return nil
        }

        return information as? [CFString: Any]
    }
}
