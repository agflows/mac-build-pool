import XCTest

final class ProbeUITests: XCTestCase {
    @MainActor func testRealAppAndNetworkBoundary() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["Isolated Build"].waitForExistence(timeout: 30))
        XCTAssertTrue(app.staticTexts["Direct network blocked"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["Approved HTTPS works"].waitForExistence(timeout: 40))
        XCTAssertFalse(app.staticTexts["Direct network escaped"].exists)
    }
}
