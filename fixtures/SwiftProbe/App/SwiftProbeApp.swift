import SwiftUI
import Network
import DequeModule

@main struct SwiftProbeApp: App {
    var body: some Scene { WindowGroup { ProbeView() } }
}

struct ProbeView: View {
    @StateObject private var model = ProbeModel()
    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "checkmark.shield.fill").font(.system(size: 64)).foregroundStyle(.green)
            Text("Isolated Build").font(.largeTitle.bold())
            Text(Deque(["Swift", "pinned package"]).joined(separator: " + "))
            Text(model.network)
            Text(model.isolation)
        }.padding().task { await model.run() }
    }
}

@MainActor final class ProbeModel: ObservableObject {
    @Published var network = "Checking approved HTTPS"
    @Published var isolation = "Checking direct network"
    func run() async {
        let connection = NWConnection(host: "192.0.2.1", port: 49001, using: .tcp)
        connection.stateUpdateHandler = { [weak self] state in
            if case .ready = state { Task { @MainActor in self?.isolation = "Direct network escaped" } }
        }
        connection.start(queue: .global())
        try? await Task.sleep(for: .seconds(3))
        connection.cancel()
        if isolation != "Direct network escaped" { isolation = "Direct network blocked" }
        do {
            var request = URLRequest(url: URL(string: "https://registry.npmjs.org/expo/58.0.23")!)
            request.timeoutInterval = 25
            let (_, response) = try await URLSession.shared.data(for: request)
            network = (response as? HTTPURLResponse)?.statusCode == 200 ? "Approved HTTPS works" : "Approved HTTPS failed"
        } catch { network = "Approved HTTPS failed" }
    }
}
