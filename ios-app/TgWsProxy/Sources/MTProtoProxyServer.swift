import Foundation
import Network
import os.log

private let logger = Logger(subsystem: "com.tgwsproxy.app", category: "ProxyServer")

// MARK: - MTProto Proxy Server

final class MTProtoProxyServer: @unchecked Sendable {
    private let config: ProxyConfig
    private var listener: NWListener?
    private var statsCallback: ((ProxyStats) -> Void)?
    private var stats = ProxyStats()

    init(config: ProxyConfig, statsCallback: ((ProxyStats) -> Void)? = nil) {
        self.config = config
        self.statsCallback = statsCallback
    }

    func start() async throws {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true

        let params = NWParameters(tls: nil, tcp: tcpOptions)

        let port = NWEndpoint.Port(rawValue: UInt16(config.port))!
        listener = try NWListener(using: params, on: port)

        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleNewConnection(connection)
        }

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            listener?.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.listener?.stateUpdateHandler = nil
                    logger.info("Proxy server listening on port \(self?.config.port ?? 0)")
                    cont.resume()

                case .failed(let error):
                    self?.listener?.stateUpdateHandler = nil
                    logger.error("Listener failed: \(error)")
                    cont.resume(throwing: error)

                case .cancelled:
                    self?.listener?.stateUpdateHandler = nil
                    cont.resume(throwing: CancellationError())

                default:
                    break
                }
            }
            listener?.start(queue: DispatchQueue.global(qos: .userInitiated))
        }

        Task { [weak self] in
            while self?.listener != nil {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard let self else { break }
                let currentStats = self.stats
                self.statsCallback?(currentStats)
            }
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    // MARK: - Connection handling

    private func handleNewConnection(_ connection: NWConnection) {
        connection.start(queue: DispatchQueue.global(qos: .userInitiated))

        stats.connectionsTotal += 1
        stats.connectionsActive += 1

        Task { [weak self] in
            guard let self else {
                connection.cancel()
                return
            }

            defer {
                self.stats.connectionsActive -= 1
                connection.cancel()
            }

            do {
                try await self.processClient(connection)
            } catch {
                logger.debug("Client connection error: \(error)")
            }
        }
    }

    private func processClient(_ connection: NWConnection) async throws {
        try await waitForReady(connection)

        let handshakeData = try await receiveExact(connection, count: HANDSHAKE_LEN)
        let handshake = [UInt8](handshakeData)

        let secretBytes = hexToBytes(config.secret)
        guard let result = tryHandshake(handshake, secret: secretBytes) else {
            stats.connectionsBad += 1
            logger.debug("Bad handshake (wrong secret or proto)")
            _ = try? await receiveData(connection, maxLength: 4096)
            return
        }

        let dcIdx = result.isMedia ? -result.dcId : result.dcId
        let relayInit = generateRelayInit(protoTag: result.protoTag, dcIdx: dcIdx)

        let cltDecPrekey = Array(result.clientDecPrekeyIV[0..<PREKEY_LEN])
        let cltDecIV = Array(result.clientDecPrekeyIV[PREKEY_LEN...])
        let cltDecKey = sha256(cltDecPrekey + secretBytes)

        let cltEncPrekeyIV = Array(result.clientDecPrekeyIV.reversed())
        let cltEncKey = sha256(Array(cltEncPrekeyIV[0..<PREKEY_LEN]) + secretBytes)
        let cltEncIV = Array(cltEncPrekeyIV[PREKEY_LEN...])

        let cltDecryptor = AESCTR(key: cltDecKey, iv: cltDecIV)
        let cltEncryptor = AESCTR(key: cltEncKey, iv: cltEncIV)

        _ = cltDecryptor.process(ZERO_64)

        let relayEncKey = Array(relayInit[SKIP_LEN ..< SKIP_LEN + PREKEY_LEN])
        let relayEncIV = Array(relayInit[SKIP_LEN + PREKEY_LEN ..< SKIP_LEN + PREKEY_LEN + IV_LEN])

        let relayDecPrekeyIV = Array(relayInit[SKIP_LEN ..< SKIP_LEN + PREKEY_LEN + IV_LEN].reversed())
        let relayDecKey = Array(relayDecPrekeyIV[0..<KEY_LEN])
        let relayDecIV = Array(relayDecPrekeyIV[KEY_LEN...])

        let tgEncryptor = AESCTR(key: relayEncKey, iv: relayEncIV)
        let tgDecryptor = AESCTR(key: relayDecKey, iv: relayDecIV)
        _ = tgEncryptor.process(ZERO_64)

        let mediaTag = result.isMedia ? "m" : ""
        logger.info("Handshake ok: DC\(result.dcId)\(mediaTag)")

        guard let targetIP = config.dcRedirects[result.dcId] else {
            if let fallbackIP = ProxyConfig.dcDefaultIPs[result.dcId] {
                logger.info("DC\(result.dcId) not in config, TCP fallback to \(fallbackIP):443")
                try await tcpFallback(
                    connection: connection, dst: fallbackIP, port: 443,
                    relayInit: relayInit,
                    cltDecryptor: cltDecryptor, cltEncryptor: cltEncryptor,
                    tgEncryptor: tgEncryptor, tgDecryptor: tgDecryptor
                )
            } else {
                logger.warning("DC\(result.dcId) — no fallback available")
            }
            return
        }

        let domains = wsDomains(dc: result.dcId, isMedia: result.isMedia, overrides: config.dcOverrides)

        var ws: RawWebSocket? = nil
        for domain in domains {
            logger.info("DC\(result.dcId)\(mediaTag) -> wss://\(domain)/apiws via \(targetIP)")
            do {
                ws = try await RawWebSocket.connect(ip: targetIP, domain: domain, timeout: 10)
                break
            } catch let error as WsHandshakeError where error.isRedirect {
                logger.warning("DC\(result.dcId)\(mediaTag) got \(error.statusCode) redirect")
                continue
            } catch {
                stats.wsErrors += 1
                logger.warning("DC\(result.dcId)\(mediaTag) WS connect failed: \(error)")
            }
        }

        guard let activeWS = ws else {
            let fallbackIP = ProxyConfig.dcDefaultIPs[result.dcId] ?? targetIP
            logger.info("DC\(result.dcId)\(mediaTag) WS failed, TCP fallback to \(fallbackIP):443")
            try await tcpFallback(
                connection: connection, dst: fallbackIP, port: 443,
                relayInit: relayInit,
                cltDecryptor: cltDecryptor, cltEncryptor: cltEncryptor,
                tgEncryptor: tgEncryptor, tgDecryptor: tgDecryptor
            )
            return
        }

        stats.connectionsWS += 1

        let splitter = MsgSplitter(relayInit: relayInit, protoInt: result.protoInt)

        try await activeWS.send(Data(relayInit))

        try await bridgeWSReencrypt(
            connection: connection, ws: activeWS,
            cltDecryptor: cltDecryptor, cltEncryptor: cltEncryptor,
            tgEncryptor: tgEncryptor, tgDecryptor: tgDecryptor,
            splitter: splitter
        )
    }

    // MARK: - Bridge WS

    private func bridgeWSReencrypt(
        connection: NWConnection, ws: RawWebSocket,
        cltDecryptor: AESCTR, cltEncryptor: AESCTR,
        tgEncryptor: AESCTR, tgDecryptor: AESCTR,
        splitter: MsgSplitter
    ) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [weak self] in
                do {
                    while true {
                        let chunk = try await self?.receiveData(connection, maxLength: 65536)
                        guard let chunk, !chunk.isEmpty else { break }

                        self?.stats.bytesUp += UInt64(chunk.count)

                        let plain = cltDecryptor.process(chunk)
                        let encrypted = tgEncryptor.process(plain)

                        let parts = splitter.split(encrypted)
                        if parts.isEmpty { continue }

                        if parts.count > 1 {
                            try await ws.sendBatch(parts)
                        } else {
                            try await ws.send(parts[0])
                        }
                    }
                } catch {
                }
                await ws.close()
            }

            group.addTask { [weak self] in
                do {
                    while true {
                        guard let data = try await ws.recv() else { break }

                        self?.stats.bytesDown += UInt64(data.count)

                        let plain = tgDecryptor.process(data)
                        let encrypted = cltEncryptor.process(plain)

                        try await self?.sendData(connection, data: encrypted)
                    }
                } catch {
                }
                connection.cancel()
            }

            try await group.next()
            group.cancelAll()
        }
    }

    // MARK: - TCP Fallback

    private func tcpFallback(
        connection: NWConnection, dst: String, port: Int,
        relayInit: [UInt8],
        cltDecryptor: AESCTR, cltEncryptor: AESCTR,
        tgEncryptor: AESCTR, tgDecryptor: AESCTR
    ) async throws {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcpOptions)

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(dst),
            port: NWEndpoint.Port(rawValue: UInt16(port))!
        )
        let remote = NWConnection(to: endpoint, using: params)
        remote.start(queue: DispatchQueue.global(qos: .userInitiated))

        try await waitForReady(remote)

        try await sendData(remote, data: Data(relayInit))

        stats.connectionsTCPFallback += 1

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [weak self] in
                do {
                    while true {
                        let data = try await self?.receiveData(connection, maxLength: 65536)
                        guard let data, !data.isEmpty else { break }

                        self?.stats.bytesUp += UInt64(data.count)

                        let plain = cltDecryptor.process(data)
                        let enc = tgEncryptor.process(plain)
                        try await self?.sendData(remote, data: enc)
                    }
                } catch {
                }
                remote.cancel()
            }

            group.addTask { [weak self] in
                do {
                    while true {
                        let data = try await self?.receiveData(remote, maxLength: 65536)
                        guard let data, !data.isEmpty else { break }

                        self?.stats.bytesDown += UInt64(data.count)

                        let plain = tgDecryptor.process(data)
                        let enc = cltEncryptor.process(plain)
                        try await self?.sendData(connection, data: enc)
                    }
                } catch {
                }
                connection.cancel()
            }

            try await group.next()
            group.cancelAll()
        }
    }

    // MARK: - NWConnection helpers

    private func waitForReady(_ connection: NWConnection) async throws {
        if connection.state == .ready { return }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.stateUpdateHandler = nil
                    cont.resume()
                case .failed(let error):
                    connection.stateUpdateHandler = nil
                    cont.resume(throwing: error)
                case .cancelled:
                    connection.stateUpdateHandler = nil
                    cont.resume(throwing: CancellationError())
                default:
                    break
                }
            }
        }
    }

    private func receiveExact(_ connection: NWConnection, count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error {
                    cont.resume(throwing: error)
                } else if let data, data.count == count {
                    cont.resume(returning: data)
                } else {
                    cont.resume(throwing: RawWebSocket.ConnectionError.closed)
                }
            }
        }
    }

    private func receiveData(_ connection: NWConnection, maxLength: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { data, _, isComplete, error in
                if let error {
                    cont.resume(throwing: error)
                } else if let data, !data.isEmpty {
                    cont.resume(returning: data)
                } else if isComplete {
                    cont.resume(returning: Data())
                } else {
                    cont.resume(throwing: RawWebSocket.ConnectionError.closed)
                }
            }
        }
    }

    private func sendData(_ connection: NWConnection, data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume()
                }
            })
        }
    }
}

// MARK: - Hex helpers

func hexToBytes(_ hex: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
        if let byte = UInt8(hex[index..<next], radix: 16) {
            bytes.append(byte)
        }
        index = next
    }
    return bytes
}
