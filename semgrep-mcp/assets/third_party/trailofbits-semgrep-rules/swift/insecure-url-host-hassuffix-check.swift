if let url = URL(string: "https://mail.google.com/mail/u/0/") {
    if let host = url.host {
        print("URL: \(url)")
        print("Host: \(host)")
        // ruleid: insecure-url-host-hassuffix-check
        if host.hasSuffix("google.com") {
            print("This is a Google domain!")
        } else {
            print("This is not a Google domain.")
        }
    }
}


if let url = URL(string: "https://mail.google.com/mail/u/0/") {
    if let host = url.host {
        print("URL: \(url)")
        print("Host: \(host)")
        // ruleid: insecure-url-host-hassuffix-check
        if host.hasSuffix("google.com") {
            print("This is a Google domain!")
        } else {
            print("This is not a Google domain.")
        }
    }
}

// ruleid: insecure-url-host-hassuffix-check
URL(string: "https://example.com")?.host?.hasSuffix("google.com")
let url = URL(string: someString)
// ruleid: insecure-url-host-hassuffix-check
url?.host?.hasSuffix("domain.com")

// ok: insecure-url-host-hassuffix-check
URL(string: "https://example.com")?.host?.hasSuffix(".google.com")
let url = URL(string: someString)
// ok: insecure-url-host-hassuffix-check
url?.host?.hasSuffix(".domain.com")


extension URL {
    /// Returns whether the URL matches Slack's top level domain.
    var isSlackHost: Bool {
        // ruleid: insecure-url-host-hassuffix-check
        host?.hasSuffix("slack.com") ?? false
    }

    public var isSlackOpenURL: Bool {
        guard
            isSlackHost,
            x[y: 1] == "z"
        else {
            return false
        }
        return true
    }
}

func case1_nestedIfLet() {
    if let url = URL(string: "https://mail.google.com/mail/u/0/") {
        if let host = url.host {
            print("URL: \(url)")
            print("Host: \(host)")
            
            // ruleid: insecure-url-host-hassuffix-check
            if host.hasSuffix("google.com") {
                print("This is a Google domain!")
            } else {
                print("This is not a Google domain.")
            }
        }
    }
}

func testDifferentVariableNames() {
    // Test with different variable names
    if let url = URL(string: "https://docs.google.com") {
        if let serverName = url.host {
            // ruleid: insecure-url-host-hassuffix-check
            if serverName.hasSuffix("google.com") {
                print("Google server")
            }
        }
    }
    
    if let url = URL(string: "https://slack.com") {
        if let domain = url.host {
            // ruleid: insecure-url-host-hassuffix-check
            if domain.hasSuffix("slack.com") {
                print("Slack domain")
            }
        }
    }
    
    let someURL = URL(string: "https://github.com")
    if let hostname = someURL?.host {
        // ruleid: insecure-url-host-hassuffix-check
        if hostname.hasSuffix("github.com") {
            print("GitHub hostname")
        }
    }
}

func case2_directChaining() {
    let urlString = "https://docs.google.com/document"
    
    // ruleid: insecure-url-host-hassuffix-check
    if URL(string: urlString)?.host?.hasSuffix("google.com") == true {
        print("Google domain detected")
    }
    
    let trusted = "https://slack.com/workspace"
    // ruleid: insecure-url-host-hassuffix-check
    if URL(string: trusted)!.host!.hasSuffix("slack.com") {
        print("Slack domain")
    }
    
    // ruleid: insecure-url-host-hassuffix-check
    if URL(string: urlString)?.host.hasSuffix("google.com") == true {
        print("Another Google check")
    }
}

extension URL {
    var isSlackHost: Bool {
        // ruleid: insecure-url-host-hassuffix-check
        host?.hasSuffix("slack.com") ?? false
    }
    
    var isGoogleHost: Bool {
        // ruleid: insecure-url-host-hassuffix-check
        self.host?.hasSuffix("google.com") ?? false
    }
    
    var isGitHubHost: Bool {
        guard let host = host else { return false }
        // ruleid: insecure-url-host-hassuffix-check
        return host.hasSuffix("github.com")
    }
    
    var isMicrosoftHost: Bool {
        // ruleid: insecure-url-host-hassuffix-check
        self.host?.hasSuffix("microsoft.com") ?? false
    }
}

func case4_urlVariable() {
    let myURL = URL(string: "https://app.slack.com/client")
    
    // ruleid: insecure-url-host-hassuffix-check
    if myURL?.host?.hasSuffix("slack.com") == true {
        print("Slack URL confirmed")
    }
    
    // Another variation
    let anotherURL = URL(string: "https://drive.google.com")
    
    // ruleid: insecure-url-host-hassuffix-check
    if anotherURL!.host?.hasSuffix("google.com") == true {
        print("Google Drive URL")
    }
    
    // ruleid: insecure-url-host-hassuffix-check
    if myURL?.host.hasSuffix("slack.com") == true {
        print("Another Slack check")
    }
}

func case5_hostExtracted() {
    let url = URL(string: "https://mail.yahoo.com")
    
    let extractedHost = url?.host
    
    // ruleid: insecure-url-host-hassuffix-check
    if extractedHost?.hasSuffix("yahoo.com") == true {
        print("Yahoo mail detected")
    }
}

func case6_directHostBinding() {
    let urlString = "https://teams.microsoft.com/meeting"
    
    
    if let host = URL(string: urlString)?.host {
    // ruleid: insecure-url-host-hassuffix-check
        if host.hasSuffix("microsoft.com") {
            print("Microsoft Teams URL")
        }
    }
}

func case7_singleIfLetURL() {
    let input = "https://calendar.google.com/calendar"
    if let url = URL(string: input) {
        // Some other logic here
        print("Processing URL: \(url)")
        
        // ruleid: insecure-url-host-hassuffix-check
        if url.host?.hasSuffix("google.com") == true {
            print("Google Calendar detected")
        }
    }
}

// Function with URL parameter
func validateDomain(url: URL) -> Bool {
    // ruleid: insecure-url-host-hassuffix-check
    return url.host?.hasSuffix("example.com") ?? false
}

// Guard let patterns
func processURL(urlString: String) {
    guard let url = URL(string: urlString) else { return }
    
    // ruleid: insecure-url-host-hassuffix-check
    guard url.host?.hasSuffix("trusted.com") == true else {
        print("Untrusted domain")
        return
    }
    
    print("Processing trusted domain")
}

// Nested guard patterns
func complexGuardPattern(input: String) {
    guard let url = URL(string: input) else { return }
    guard let host = url.host else { return }
    
    // ruleid: insecure-url-host-hassuffix-check
    if host.hasSuffix("secure.net") {
        print("Secure network domain")
    }
}

// Class/Struct with URL property
class URLValidator {
    let url: URL
    
    init?(urlString: String) {
        guard let url = URL(string: urlString) else { return nil }
        self.url = url
    }
    
    func isCompanyDomain() -> Bool {
        // ruleid: insecure-url-host-hassuffix-check
        return url.host?.hasSuffix("company.com") ?? false
    }
}

// Switch statement with multiple domains
func categorizeURL(_ urlString: String) {
    guard let url = URL(string: urlString),
          let host = url.host else { return }
    
    switch true {
    // ruleid: insecure-url-host-hassuffix-check
    case host.hasSuffix("google.com"):
        print("Google service")
    // ruleid: insecure-url-host-hassuffix-check
    case host.hasSuffix("microsoft.com"):
        print("Microsoft service")
    // ruleid: insecure-url-host-hassuffix-check
    case host.hasSuffix("apple.com"):
        print("Apple service")
    default:
        print("Other service")
    }
}

func correctExamples() {
    if let url = URL(string: "https://mail.google.com") {
        if let host = url.host {
            // ok: insecure-url-host-hassuffix-check
            if host.hasSuffix(".google.com") {
                print("Google subdomain")
            }
            
            // ok: insecure-url-host-hassuffix-check
            if host.hasSuffix(".google.com") || host == "google.com" {
                print("Google domain or subdomain")
            }
        }
    }
}

extension URL {
    // ok: insecure-url-host-hassuffix-check
    var isProperSlackHost: Bool {
        guard let host = host else { return false }
        return host.hasSuffix(".slack.com") || host == "slack.com"
    }
}

// Normal string operations - should NOT be flagged
func normalStringOperations() {
    let email = "user@google.com"
    // ok: insecure-url-host-hassuffix-check
    if email.hasSuffix("google.com") {
        print("Google email")
    }
    
    let filename = "document.google.com"
    // ok: insecure-url-host-hassuffix-check
    if filename.hasSuffix("google.com") {
        print("Filename ends with google.com")
    }
    
    let randomString = "This is not a URL but ends with microsoft.com"
    // ok: insecure-url-host-hassuffix-check
    if randomString.hasSuffix("microsoft.com") {
        print("String ends with microsoft.com")
    }
    
    let userInput = getUserInput()
    // ok: insecure-url-host-hassuffix-check
    if userInput.hasSuffix("apple.com") {
        print("User input ends with apple.com")
    }
}

// More edge cases
func edgeCases() {
    // URLComponents host check
    var components = URLComponents(string: "https://docs.google.com")
    // ruleid: insecure-url-host-hassuffix-check
    if components?.host?.hasSuffix("google.com") == true {
        print("Google docs")
    }
    
    // Computed property
    struct Request {
        let url: URL
        
        var isGoogleDomain: Bool {
            // ruleid: insecure-url-host-hassuffix-check
            url.host?.hasSuffix("google.com") ?? false
        }
    }
    
    // Closure with URL
    let checkDomain: (URL) -> Bool = { url in
        // ruleid: insecure-url-host-hassuffix-check
        url.host?.hasSuffix("example.com") ?? false
    }
    
    // Array of URLs
    let urls = [URL(string: "https://mail.google.com")!]
    for url in urls {
        // ruleid: insecure-url-host-hassuffix-check
        if url.host?.hasSuffix("google.com") == true {
            print("Found Google URL")
        }
    }
}