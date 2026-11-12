import SwiftUI

@main
struct WatchProbe: App {
    var body: some Scene {
        WindowGroup {
            VStack(spacing: 8) {
                Image(systemName: "applewatch")
                    .font(.title)
                Text("Watch build")
                    .font(.headline)
                Text("Isolated simulator")
                    .font(.caption)
            }
        }
    }
}
