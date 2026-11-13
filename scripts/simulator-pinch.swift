import FBControlCore
import FBSimulatorControl
import Foundation

@main
struct SimulatorPinch {
    enum InputError: Error {
        case invalidArguments
        case simulatorUnavailable
        case gestureOutsideDisplay
    }

    @MainActor
    static func main() async throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments.count == 5,
              let target = UUID(uuidString: arguments[0]),
              let scale = Double(arguments[1]), scale.isFinite, (0.1...10).contains(scale), scale != 1
        else { throw InputError.invalidArguments }

        let logger = FBControlCoreGlobalConfiguration.defaultLogger
        try FBSimulatorControlFrameworkLoader.xcodeFrameworks.loadPrivateFrameworks(logger)
        let configuration = FBSimulatorControlConfiguration(deviceSetPath: nil, logger: logger, reporter: nil)
        let control = try FBSimulatorControl.withConfiguration(configuration)
        guard let simulator = control.set.allSimulators.first(where: { $0.udid == target.uuidString }),
              simulator.state == .booted,
              let display = simulator.screenInfo, display.scale > 0
        else { throw InputError.simulatorUnavailable }

        let width = Double(display.widthPixels) / Double(display.scale)
        let height = Double(display.heightPixels) / Double(display.scale)
        let x = try coordinate(arguments[2], defaultValue: width / 2)
        let y = try coordinate(arguments[3], defaultValue: height / 2)
        // The Indigo transport expects native portrait points and uses horizontal contacts.
        let maximumRadius = min(x, width - x) / max(1, scale)
        let radius = try coordinate(arguments[4], defaultValue: min(width / 4, maximumRadius - 1))
        guard y >= 0, y < height, radius >= 1, radius < maximumRadius
        else { throw InputError.gestureOutsideDisplay }

        let hid = try await simulator.connectToHID()
        defer { hid.disconnect() }
        try await hid.send(event: .pinchAt(x: x, y: y, scale: scale, duration: 0.6, radius: radius), logger: logger)
    }

    private static func coordinate(_ argument: String, defaultValue: Double) throws -> Double {
        if argument == "-" { return defaultValue }
        guard let value = Double(argument), value.isFinite else { throw InputError.invalidArguments }
        return value
    }
}
