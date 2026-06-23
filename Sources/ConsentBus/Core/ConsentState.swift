import Foundation

/// Represents the lifecycle state of user consent for a given purpose.
///
/// Patent reference: Provisional Application No. 64/087,949, Section VII —
/// ConsentState Finite-State Machine.
public enum ConsentState: String, Codable, Sendable {
    case unknown
    case pending
    case granted
    case revoked
    case expired
}

/// The taxonomy of consent purposes ConsentBus can propagate.
///
/// Designed to normalize across IAB TCF v2.2, Google Consent Mode v2,
/// and emerging per-intent operating system privacy declaration categories.
public enum ConsentPurpose: String, Codable, Sendable, CaseIterable {
    case analyticsStorage
    case adStorage
    case adPersonalization
    case adUserData
    case functional
    case locationPrecise
    case locationApproximate
    case personalization
    case measurement
    case guardianMediated
}

/// The origin of a consent signal.
public enum ConsentSource: String, Codable, Sendable {
    case userUI
    case cmp
    case osSignal
    case api
    case guardianAccount
}

/// Finite-state machine enforcing valid consent state transitions.
///
/// Patent reference: Claim 9 (dependent on Claim 1) — FSM validation
/// prior to any SDK adapter dispatch.
public struct ConsentFSM {
    private var current: ConsentState = .unknown

    private let validTransitions: [ConsentState: Set<ConsentState>] = [
        .unknown: [.pending, .granted, .revoked],
        .pending: [.granted, .revoked],
        .granted: [.revoked, .expired],
        .revoked: [.pending, .granted],
        .expired: [.pending]
    ]

    public init() {}

    public var currentState: ConsentState { current }

    @discardableResult
    public mutating func transition(to next: ConsentState) throws -> ConsentState {
        guard validTransitions[current]?.contains(next) == true else {
            throw ConsentError.invalidTransition(from: current, to: next)
        }
        current = next
        return current
    }
}

public enum ConsentError: Error, CustomStringConvertible {
    case invalidTransition(from: ConsentState, to: ConsentState)

    public var description: String {
        switch self {
        case .invalidTransition(let from, let to):
            return "Invalid consent transition: \(from.rawValue) -> \(to.rawValue)"
        }
    }
}
