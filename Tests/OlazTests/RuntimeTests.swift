import Testing
import Foundation
@testable import Olaz

/// The bridge must reproduce Node's crypto byte-for-byte: the official renderer
/// encrypts `zcid` and request params through `$znode.crypto`. Expected values
/// were produced by Node 26 (`crypto.createCipheriv` & co.).
@MainActor
@Suite struct CryptoBridgeParity {
    private func call(_ bridge: ZaloBridge, _ path: String, _ args: [Any]) throws -> Any? {
        let body = try JSONSerialization.data(withJSONObject: ["path": path, "args": args.map { ZaloBridge.toJS($0) }])
        let response = try JSONSerialization.jsonObject(with: bridge.handleSyncRequest(body)) as! [String: Any]
        if let error = response["error"] as? String { throw ZaloBridge.BridgeError(message: error) }
        return response["value"].map(ZaloBridge.fromJS)
    }

    private func makeBridge() -> ZaloBridge {
        let bridge = ZaloBridge()
        CryptoBridge.install(on: bridge)
        return bridge
    }

    @Test func zcidEncryptMatchesNode() throws {
        let out = try call(makeBridge(), "$znode.crypto.encrypt", [
            "23,abc-imei,1792963077777", "aes-256-cbc", "3FC4F0D2AB50057BCE0D90D9187A22B1", NSNull(),
            ["key": "utf-8", "input": "utf-8", "output": "hex"],
        ])
        #expect(out as? String == "a1a69db6a344da4d883865c637f979495dd86112a4534347b462259bfdeb641b")
    }

    @Test func paramsRoundTripBase64() throws {
        let bridge = makeBridge()
        let key = "DE71B7D4C57C0749158CB90D5E431AE3"
        let encrypted = try call(bridge, "$znode.crypto.encrypt", [
            "{\"language\":\"vi\"}", "aes-256-cbc", key, NSNull(), ["key": "utf-8", "input": "utf-8", "output": "base64"],
        ])
        #expect(encrypted as? String == "V5p1S6tTwaE91W8UDCagn9vVP9wUQ3QzA04wG7xh+5E=")
        let decrypted = try call(bridge, "$znode.crypto.decrypt", [
            encrypted!, "aes-256-cbc", key, NSNull(), ["key": "utf-8", "input": "base64", "output": "utf-8"],
        ])
        #expect(decrypted as? String == "{\"language\":\"vi\"}")
    }

    @Test func streamingCTRAndGCM() throws {
        let bridge = makeBridge()
        let ctr = try call(bridge, "$znode.crypto.__cipherCreate", ["cipher", "aes-128-ctr", Data(repeating: 7, count: 16), Data(repeating: 1, count: 16)]) as! Int
        let ctrOut = try call(bridge, "$znode.crypto.__cipherUpdate", [ctr, "hello zalo ctr mode!", "utf8", "hex"]) as? String
        #expect(ctrOut == "324a84ef5fc3a21b11456b948b319aab1c6e924d")

        let gcm = try call(bridge, "$znode.crypto.__cipherCreate", ["cipher", "aes-256-gcm", Data(repeating: 3, count: 32), Data(repeating: 9, count: 12)]) as! Int
        _ = try call(bridge, "$znode.crypto.__cipherUpdate", [gcm, "gcm payload", "utf8", NSNull()])
        let sealed = try call(bridge, "$znode.crypto.__cipherFinal", [gcm, "hex"]) as? String
        #expect(sealed == "636b00fbfe1c3505e56f0c")
        let tag = try call(bridge, "$znode.crypto.__cipherOption", [gcm, "getAuthTag"]) as? Data
        #expect(tag?.map { String(format: "%02x", $0) }.joined() == "377ee9d6cfa423566629c0cfbb8eb885")
    }

    @Test func hashes() throws {
        let bridge = makeBridge()
        let h = try call(bridge, "$znode.crypto.__hashCreate", ["md5"]) as! Int
        _ = try call(bridge, "$znode.crypto.__hashUpdate", [h, "841630ae41f", NSNull()])
        #expect(try call(bridge, "$znode.crypto.__hashDigest", [h, "hex"]) as? String == "d9e97c18b27cd54e969268d9b39e8680")
        #expect(try call(bridge, "$znode.crypto.hash", ["zalo", "sha256", NSNull(), "base64"]) as? String
                == "PpYUHCFwTpavYlfqQcD8aQzgUEyFKdxCTciyRbY0PA8=")
    }

    @Test func badDecryptThrows() {
        #expect(throws: (any Error).self) {
            try call(makeBridge(), "$znode.crypto.decrypt", [
                "AAAAAAAAAAAAAAAAAAAAAA==", "aes-256-cbc", "DE71B7D4C57C0749158CB90D5E431AE3", NSNull(),
                ["key": "utf-8", "input": "base64", "output": "utf-8"],
            ])
        }
    }
}

@Suite struct AsarReading {
    /// Builds a minimal asar: header pickle + two files.
    private func makeArchive() throws -> URL {
        let files: [(String, Data)] = [("pc-dist/login.html", Data("<html>hi</html>".utf8)), ("pc-dist/lazy/a.js", Data("1+1".utf8))]
        var offset = 0
        var tree: [String: Any] = [:]
        var payload = Data()
        for (path, data) in files {
            let parts = path.split(separator: "/").map(String.init)
            func insert(_ node: inout [String: Any], _ rest: ArraySlice<String>) {
                var files = node["files"] as? [String: Any] ?? [:]
                if rest.count == 1 {
                    files[rest.first!] = ["size": data.count, "offset": String(offset)]
                } else {
                    var child = files[rest.first!] as? [String: Any] ?? [:]
                    insert(&child, rest.dropFirst())
                    files[rest.first!] = child
                }
                node["files"] = files
            }
            insert(&tree, parts[...])
            payload.append(data)
            offset += data.count
        }
        let json = try JSONSerialization.data(withJSONObject: tree)
        func u32(_ v: Int) -> Data { withUnsafeBytes(of: UInt32(v).littleEndian) { Data($0) } }
        let padded = (json.count + 3) & ~3
        let headerPickle = u32(padded + 4) + u32(json.count) + json + Data(count: padded - json.count)
        let archive = u32(4) + u32(headerPickle.count) + headerPickle + payload
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("olaz-test-\(UUID()).asar")
        try archive.write(to: url)
        return url
    }

    @Test func readsFilesFromArchive() throws {
        let asar = try AsarArchive(url: try makeArchive())
        #expect(asar.read("pc-dist/login.html").map { String(decoding: $0, as: UTF8.self) } == "<html>hi</html>")
        #expect(asar.read("/pc-dist/lazy/a.js").map { String(decoding: $0, as: UTF8.self) } == "1+1")
        #expect(asar.read("pc-dist/missing.js") == nil)
        #expect(asar.paths(withPrefix: "pc-dist/lazy").count == 1)
    }

    @Test func installedZaloIsReadableWhenPresent() throws {
        guard FileManager.default.fileExists(atPath: OfficialZaloInstall.defaultAppURL.path) else { return }
        let info = try OfficialZaloInstall.locate()
        #expect(info.asar.contains("pc-dist/login.html"))
        #expect(info.asar.contains("pc-dist/index.html"))
    }
}

@MainActor
@Suite struct SessionCookies {
    /// The realtime socket (`wss://wsN-msg.chat.zalo.me`) must receive `zpw_sek`,
    /// as Electron's domain cookies did; a host-only cookie silently breaks it.
    @Test func appCookieReachesRealtimeAndAPIHosts() {
        let storage = HTTPCookieStorage.sharedCookieStorage(forGroupContainerIdentifier: "olaz.tests.\(UUID())")
        for domain in ZaloMainProcess.sessionCookieDomains {
            ZaloMainProcess.setCookie(name: "zpw_sek", value: "test", domain: domain, days: 1, httpOnly: true, storage: storage)
        }
        for host in ["https://ws5-msg.chat.zalo.me/", "https://chat.zalo.me/", "https://wpa.zaloapp.com/", "https://tt-profile-wpa.zaloapp.com/"] {
            let names = storage.cookies(for: URL(string: host)!)?.map(\.name) ?? []
            #expect(names.contains("zpw_sek"), "missing zpw_sek for \(host)")
        }
    }
}

@MainActor
@Suite struct QRLoginStateTests {
    private let pollURL = URL(string: "https://qr-id.zaloapp.com/polling/qr/waiting")!

    @Test func decodeDataURLSupportsBase64AndPercentEncodedSVG() {
        let rawPNG = Data([0x89, 0x50, 0x4E, 0x47])
        let base64URL = "data:image/png;base64," + rawPNG.base64EncodedString()
        #expect(ZaloEngine.decodeDataURL(base64URL) == rawPNG)

        let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\"><rect width=\"100%\" height=\"100%\" fill=\"white\"/></svg>"
        let encodedSVG = svg.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let svgURL = "data:image/svg+xml;utf8," + encodedSVG
        let decoded = ZaloEngine.decodeDataURL(svgURL)
        #expect(decoded.flatMap { String(data: $0, encoding: .utf8) } == svg)
    }

    @Test func multiLayerQR2RotationAndTransientCodesStayWaitingScan() throws {
        let engine = ZaloEngine()
        engine.phase = .login(ZaloEngine.LoginState())
        let firstSVG = "data:image/svg+xml;utf8,%3Csvg%20id%3D%22qr1%22%2F%3E"
        let secondSVG = "data:image/svg+xml;utf8,%3Csvg%20id%3D%22qr2%22%2F%3E"

        // Initial QR1 arrives
        engine.handle(state: ["page": "login", "event": "qr", "qr": firstSVG])
        guard case .login(let s1) = engine.phase else { Issue.record("expected .login"); return }
        #expect(s1.step == .waitingScan)
        #expect(String(data: s1.qrPNG ?? Data(), encoding: .utf8) == "<svg id=\"qr1\"/>")

        // Server returns error_code = -20 ("Vui lòng thử lại QR mới.") to trigger second-layer QR
        let pollMinus20 = try JSONSerialization.data(withJSONObject: [
            "error_code": -20,
            "error_message": "Vui lòng thử lại QR mới.",
            "data": ["qr_cnt": "token2", "base64_qr": ""],
        ])
        engine.observe(url: pollURL, status: 200, body: pollMinus20)
        guard case .login(let s2) = engine.phase else { Issue.record("expected .login"); return }
        #expect(s2.step == .waitingScan)

        // Official client finishes genSecondQR and posts event = "qr2"
        engine.handle(state: ["page": "login", "event": "qr2", "qr": secondSVG])
        guard case .login(let s3) = engine.phase else { Issue.record("expected .login"); return }
        #expect(s3.step == .waitingScan)
        #expect(String(data: s3.qrPNG ?? Data(), encoding: .utf8) == "<svg id=\"qr2\"/>")

        // Transient 18010 status keeps waitingScan
        let poll18010 = try JSONSerialization.data(withJSONObject: [
            "error_code": 18010,
            "error_message": "Waiting...",
        ])
        engine.observe(url: pollURL, status: 200, body: poll18010)
        if case .login(let s4) = engine.phase {
            #expect(s4.step == .waitingScan)
        } else {
            Issue.record("expected .login")
        }

        // User scans QR2 → display_name arrives → waitingConfirm
        let pollScanned = try JSONSerialization.data(withJSONObject: [
            "error_code": 0,
            "data": ["display_name": "Nguyen Van A", "avatar": "https://s120-ava-talk.zadn.vn/a.jpg"],
        ])
        engine.observe(url: pollURL, status: 200, body: pollScanned)
        if case .login(let s5) = engine.phase {
            #expect(s5.step == .waitingConfirm(name: "Nguyen Van A", avatar: URL(string: "https://s120-ava-talk.zadn.vn/a.jpg")))
        } else {
            Issue.record("expected .login")
        }
    }

    @Test func relinkFailureAndTimeoutTransitionToExpired() throws {
        let engine = ZaloEngine()
        engine.phase = .login(ZaloEngine.LoginState())
        engine.handle(state: ["page": "login", "event": "qr", "qr": "data:image/svg+xml;utf8,%3Csvg%2F%3E"])

        let pollMinus21 = try JSONSerialization.data(withJSONObject: [
            "error_code": -21,
            "error_message": "Relink failed",
        ])
        engine.observe(url: pollURL, status: 200, body: pollMinus21)
        if case .login(let state) = engine.phase {
            #expect(state.step == .expired)
        } else {
            Issue.record("expected .login")
        }
    }
}
