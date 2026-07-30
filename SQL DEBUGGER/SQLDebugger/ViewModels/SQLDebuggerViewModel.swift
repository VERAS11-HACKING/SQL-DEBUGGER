import Foundation
import Combine

class SQLDebuggerViewModel: ObservableObject {

    // User SQL Query
    @Published var query: String = ""

    // Vulnerability Results
    @Published var reports: [SecurityReport] = []

    // Scanner Engine
    private let scanner = SecurityScanner()

    // Start Security Scan
    func analyze() {
        reports = scanner.scan(query: query)
    }
}
