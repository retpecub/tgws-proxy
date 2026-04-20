import Foundation
import Network
import os.log

private let logger = Logger(subsystem: "com.tgwsproxy.app", category: "RawWebSocket")

struct WsHandshakeError: Error {
    let statusCode: Int
    let statusLine: String
    let headers: [String: String]
    let location: String?

    var isRedirect: Bool {
        [301, 302, 303, 307, 308].contains(statusCode)
    }
}

actor RawWebSocket {
    private var connection: NWConnection?
    private var isClosed = false
    private var receiveBuffer = Data()

    static let opBinary: UInt8 = 0x2
    static let opClose: UInt8  = 0x8
    static let opPing: UInt8   = 0x9
    static let opPong: UInt8   = 0xA

    init() {}

    static func connect(ip: String, domain: String, path: String = "/apiws",
                        timeout: TimeInterval = 10.0) async throws -> RawWebSocket {
        let ws = RawWebSocket()
        try await ws.performConnect(ip: ip, domain: domain, path: path, timeout: timeout)
        return ws
    }

    private func performConnect(ip: String, domain: String, path: String,
                                timeout: TimeInterval) async throws {
        let tlsOptions = NWProtocolTLS.Options()

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        tcpOptions.connectionTimeout = Int(timeout)

        let params = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(ip), port: NWEndpoint.Port(rawValue: 443)!)
        let conn = NWConnection(to: endpoint, using: params)

        self.connection = conn

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.stateUpdateHandler = nil
                    cont.resume()
                case .failed(let error):
                    conn.stateUpdateHandler = nil
                    cont.resume(throwing: error)
                case .cancelled:
                    conn.stateUpdateHandler = nil
                    cont.resume(throwing: CancellationError())
                default:
                    break
                }
            }
            conn.start(queue: DispatchQueue.global())
        }

        let request = "GET \(path) HTTP/1.1\r\nHost: \(domain)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"
        try await sendRaw(request.data(using: .utf8)!)
    }

    func send(_ data: Data) async throws {
        guard !isClosed else { return }
        try await sendRaw(data)
    }

    func recv() async throws -> Data? {
        return try await receiveRaw(maxLength: 65536)
    }

    func close() async {
        isClosed = true
        connection?.cancel()
    }

    private func sendRaw(_ data: Data) async throws {
        guard let conn = connection else { return }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { _ in cont.resume() })
        }
    }

    private func receiveRaw(maxLength: Int) async throws -> Data {
        guard let conn = connection else { return Data() }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            conn.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { data, _, _, _ in
                cont.resume(returning: data ?? Data())
            }
        }
    }
}
