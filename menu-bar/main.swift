import AppKit
import Darwin

private struct OwnerReply: Decodable {
    let ok: Bool
    let state: String?
    let sessionName: String?
    let leaseId: String?
    let diskBytes: Int64?
    let memoryBytes: Int64?
    let memoryMetric: String?
    let instructions: String?
}

private func request(_ operation: String, lease: String? = nil) -> OwnerReply? {
    guard let broker = getpwnam("iosbroker") else { return nil }
    let brokerUID = broker.pointee.pw_uid
    var body = ["op": operation]
    if let lease { body["leaseId"] = lease }
    guard var data = try? JSONEncoder().encode(body) else { return nil }
    data.append(10)
    for name in ["public", "validation"] {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = Array("/Library/ios-worker/owner/\(name).sock".utf8CString)
        let fits = withUnsafeMutableBytes(of: &address.sun_path) { destination in
            guard path.count <= destination.count else { return false }
            destination.copyBytes(from: path.map { UInt8(bitPattern: $0) })
            return true
        }
        guard fits else { continue }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { continue }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(descriptor, &uid, &gid) == 0, uid == brokerUID else { continue }
        var timeout = timeval(tv_sec: operation == "release" ? 95 : 20, tv_usec: 0)
        var noSignal: Int32 = 1
        setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        let written = data.withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, 0) }
        guard written == data.count else { continue }
        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while response.count < 4096 {
            let count = recv(descriptor, &buffer, buffer.count, 0)
            guard count > 0 else { break }
            response.append(contentsOf: buffer.prefix(count))
            if response.last == 10, let reply = try? JSONDecoder().decode(OwnerReply.self, from: response) {
                return reply
            }
        }
    }
    return nil
}

final class BuildPoolMenu: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let state = NSMenuItem()
    private let session = NSMenuItem()
    private let disk = NSMenuItem()
    private let memory = NSMenuItem()
    private lazy var end = NSMenuItem(title: "End Session", action: #selector(endSession), keyEquivalent: "")
    private lazy var copy = NSMenuItem(title: "Copy Agent Instructions", action: #selector(copyAgentInstructions), keyEquivalent: "")
    private var lease: String?
    private var busy = false
    private var timer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSMenu()
        menu.autoenablesItems = false
        menu.delegate = self
        for item in [state, session, disk, memory] {
            item.isEnabled = false
            menu.addItem(item)
        }
        disk.toolTip = "Allocated storage for the installed worker. Shared clone blocks can appear in more than one image."
        menu.addItem(.separator())
        copy.target = self
        menu.addItem(copy)
        end.target = self
        menu.addItem(end)
        let quit = NSMenuItem(title: "Quit Mac Build Pool", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.target = NSApp
        menu.addItem(quit)
        statusItem.menu = menu
        display(nil)
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func menuWillOpen(_ menu: NSMenu) {
        refresh()
    }

    private func display(_ reply: OwnerReply?) {
        let status = reply?.state ?? "Worker offline"
        state.title = status
        lease = reply?.leaseId
        session.title = reply?.sessionName ?? "No active session"
        disk.title = "Disk  " + format(reply?.diskBytes, style: .file)
        let showsFootprint = reply?.memoryMetric == "footprint"
        let memoryLabel = showsFootprint ? "Memory footprint" : "Resident memory"
        memory.title = memoryLabel + "  " + format(reply?.memoryBytes, style: .memory)
        memory.toolTip = showsFootprint
            ? "Combined macOS memory footprint for the broker, VM, and their helper processes."
            : "RAM currently resident for the worker processes."
        end.isEnabled = lease != nil && !busy
        let symbol = lease == nil ? "hammer" : "hammer.fill"
        statusItem.button?.image = NSImage(systemSymbolName: symbol, accessibilityDescription: "Mac Build Pool, \(status)")
        statusItem.button?.toolTip = "Mac Build Pool — \(status)"
    }

    private func format(_ bytes: Int64?, style: ByteCountFormatter.CountStyle) -> String {
        guard let bytes else { return "Unavailable" }
        return ByteCountFormatter.string(fromByteCount: bytes, countStyle: style)
    }

    private func refresh() {
        guard !busy else { return }
        busy = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let reply = request("status")
            DispatchQueue.main.async { [weak self] in
                self?.busy = false
                self?.display(reply)
            }
        }
    }

    @objc private func copyAgentInstructions() {
        copy.isEnabled = false
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let reply = request("agent_instructions")
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                if reply?.ok == true, let instructions = reply?.instructions {
                    let pasteboard = NSPasteboard.general
                    let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
                    pasteboard.declareTypes([.string, concealed], owner: nil)
                    pasteboard.setData(Data(), forType: concealed)
                    self.copy.title = pasteboard.setString(instructions, forType: .string)
                        ? "Agent Instructions Copied" : "Couldn’t Copy Agent Instructions"
                } else {
                    self.copy.title = "Agent Instructions Unavailable"
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
                    self?.copy.title = "Copy Agent Instructions"
                    self?.copy.isEnabled = true
                }
            }
        }
    }

    @objc private func endSession() {
        guard let lease, !busy else { return }
        busy = true
        end.isEnabled = false
        state.title = "Stopping"
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let reply = request("release", lease: lease)
            DispatchQueue.main.async { [weak self] in
                self?.busy = false
                if reply?.ok != true {
                    self?.state.title = "Couldn’t end the session"
                    self?.end.isEnabled = true
                    return
                }
                self?.refresh()
            }
        }
    }
}

let delegate = BuildPoolMenu()
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
app.delegate = delegate
app.run()
