import SwiftUI


struct ContentView: View {


    @StateObject private var viewModel =
    SQLDebuggerViewModel()



    var body: some View {


        NavigationStack {


            VStack(spacing: 20) {


                Text("SQL Guardian Pro")
                    .font(.largeTitle)
                    .bold()



                Text("SQL Vulnerability Scanner")
                    .foregroundColor(.gray)



                // SQL Input Area

                TextEditor(text: $viewModel.query)

                    .font(.system(.body, design: .monospaced))

                    .frame(height: 200)

                    .padding(8)

                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(.gray, lineWidth: 1)
                    )



                // Scan Button

                Button {


                    viewModel.analyze()


                } label: {


                    Text("Analyze SQL Query")

                        .frame(maxWidth: .infinity)

                }

                .buttonStyle(.borderedProminent)



                // Results

                if viewModel.reports.isEmpty {


                    Text("No vulnerabilities detected")

                        .foregroundColor(.green)

                        .padding()


                }


                List(viewModel.reports) { report in



                    VStack(alignment: .leading, spacing: 8) {



                        Text("⚠️ \(report.attackName)")

                            .font(.headline)



                        Text("Category: \(report.category)")



                        Text("Severity: \(report.severity)")



                        Text("Risk Score: \(report.riskScore)/100")



                        Text("CWE: \(report.cwe)")



                        Divider()



                        Text("Description:")

                            .bold()



                        Text(report.description)



                        Text("Solution:")

                            .bold()



                        Text(report.solution)



                    }

                    .padding(.vertical, 8)


                }



            }

            .padding()

            .navigationTitle("Security Scanner")


        }


    }


}
