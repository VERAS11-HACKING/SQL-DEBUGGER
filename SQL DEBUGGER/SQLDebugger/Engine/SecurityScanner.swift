import Foundation


class SecurityScanner {


    func scan(query: String) -> [SecurityReport] {


        var reports: [SecurityReport] = []


        let sql = query.uppercased()



        // 1. SQL Injection

        if sql.contains("' OR")
            || sql.contains("OR 1=1")
            || sql.contains("OR '1'='1") {


            reports.append(

                SecurityReport(

                    attackName: "SQL Injection",

                    category: "Injection Attack",

                    severity: "CRITICAL",

                    riskScore: 95,

                    cwe: "CWE-89",

                    description:
                    "User input can modify SQL logic and bypass authentication.",

                    solution:
                    "Use prepared statements and parameterized queries."

                )

            )
        }



        // 2. UNION SQL Injection

        if sql.contains("UNION SELECT") {


            reports.append(

                SecurityReport(

                    attackName: "UNION Based SQL Injection",

                    category: "Data Extraction",

                    severity: "CRITICAL",

                    riskScore: 90,

                    cwe: "CWE-89",

                    description:
                    "Attacker may extract information from another database table.",

                    solution:
                    "Validate input and restrict database permissions."

                )

            )

        }



        // 3. Boolean Based Injection

        if sql.contains("AND TRUE")
            || sql.contains("AND FALSE") {


            reports.append(

                SecurityReport(

                    attackName:
                    "Boolean Based SQL Injection",

                    category:
                    "Blind Injection",

                    severity:
                    "HIGH",

                    riskScore:
                    85,

                    cwe:
                    "CWE-89",

                    description:
                    "Database response can reveal information through conditions.",

                    solution:
                    "Use secure query parameters."

                )

            )

        }



        // 4. Time Based SQL Injection

        if sql.contains("SLEEP(")
            || sql.contains("WAITFOR")
            || sql.contains("BENCHMARK(") {


            reports.append(

                SecurityReport(

                    attackName:
                    "Time Based SQL Injection",

                    category:
                    "Blind Injection",

                    severity:
                    "HIGH",

                    riskScore:
                    85,

                    cwe:
                    "CWE-89",

                    description:
                    "Delay functions are used to extract database information.",

                    solution:
                    "Block dangerous SQL functions."

                )

            )

        }



        // 5. SQL Comment Injection

        if sql.contains("--")
            || sql.contains("/*") {


            reports.append(

                SecurityReport(

                    attackName:
                    "SQL Comment Injection",

                    category:
                    "Injection Attack",

                    severity:
                    "HIGH",

                    riskScore:
                    80,

                    cwe:
                    "CWE-89",

                    description:
                    "SQL comments may bypass security conditions.",

                    solution:
                    "Sanitize and validate user input."

                )

            )

        }



        // 6. Sensitive Data Exposure

        if sql.contains("SELECT *") {


            reports.append(

                SecurityReport(

                    attackName:
                    "Sensitive Data Exposure",

                    category:
                    "Information Disclosure",

                    severity:
                    "MEDIUM",

                    riskScore:
                    50,

                    cwe:
                    "CWE-200",

                    description:
                    "Query exposes unnecessary database columns.",

                    solution:
                    "Select only required fields."

                )

            )

        }



        // 7. Password Exposure

        if sql.contains("PASSWORD")
            || sql.contains("PASSWD") {


            reports.append(

                SecurityReport(

                    attackName:
                    "Password Data Exposure",

                    category:
                    "Data Leakage",

                    severity:
                    "HIGH",

                    riskScore:
                    75,

                    cwe:
                    "CWE-312",

                    description:
                    "Password information is directly accessed.",

                    solution:
                    "Hash passwords and limit access."

                )

            )

        }



        // 8. DROP Attack

        if sql.contains("DROP TABLE")
            || sql.contains("DROP DATABASE") {


            reports.append(

                SecurityReport(

                    attackName:
                    "Database Destruction Attack",

                    category:
                    "Destructive Query",

                    severity:
                    "CRITICAL",

                    riskScore:
                    100,

                    cwe:
                    "CWE-20",

                    description:
                    "Database objects can be permanently deleted.",

                    solution:
                    "Restrict destructive database permissions."

                )

            )

        }



        // 9. DELETE Without WHERE

        if sql.contains("DELETE FROM")
            && !sql.contains("WHERE") {


            reports.append(

                SecurityReport(

                    attackName:
                    "Mass Data Deletion",

                    category:
                    "Data Integrity",

                    severity:
                    "CRITICAL",

                    riskScore:
                    90,

                    cwe:
                    "CWE-749",

                    description:
                    "Delete operation affects the complete table.",

                    solution:
                    "Always use WHERE condition."

                )

            )

        }



        // 10. Privilege Escalation

        if sql.contains("GRANT ALL")
            || sql.contains("CREATE USER") {


            reports.append(

                SecurityReport(

                    attackName:
                    "Privilege Escalation",

                    category:
                    "Access Control",

                    severity:
                    "HIGH",

                    riskScore:
                    85,

                    cwe:
                    "CWE-269",

                    description:
                    "Unauthorized privilege assignment detected.",

                    solution:
                    "Apply least privilege access."

                )

            )

        }



        // 11. TRUNCATE Attack

        if sql.contains("TRUNCATE TABLE") {


            reports.append(

                SecurityReport(

                    attackName:
                    "Table Wipe Attack",

                    category:
                    "Destructive Query",

                    severity:
                    "CRITICAL",

                    riskScore:
                    95,

                    cwe:
                    "CWE-20",

                    description:
                    "All records in the table can be removed.",

                    solution:
                    "Restrict truncate permissions."

                )

            )

        }



        return reports

    }

}
