import Foundation

struct SecurityReport: Identifiable {

    let id = UUID()

    var attackName: String

    var category: String

    var severity: String

    var riskScore: Int

    var cwe: String

    var description: String

    var solution: String
}
