# malicious-code-ruleset

## Purpose

This repository contains Semgrep rules to detect dynamic code execution and obfuscation, patterns found in most malicious code incidents reported to this day. Only rules with low false-positive rates and strong correlation with malicious code are included.

## Supported Languages

Bash, Clojure, C#, Dart, Go, Java, JavaScript, TypeScript, Lua, PHP, Python, Ruby, Rust, Scala

## Installation

1. Install [Semgrep](https://semgrep.dev/docs/getting-started):
   ```bash
   pip install semgrep
   ```
   Opengrep or any other Semgrep fork could also be used.
2. Clone this repository:
   ```bash
   git clone https://github.com/apiiro/malicious-code-ruleset.git
   ```
3. Run Semgrep with the following command:
   ```bash
   semgrep --config ./malicious-code-ruleset
   ```
   Notice that Semgrep loads the rules corresponding to the extensions of the code files.

## Usage

This ruleset was developed for integration with any CI/CD pipeline, enabling detection at any stage. To monitor pull requests in real-time using this ruleset, enforce policies and trigger workflows, check out Apiiro's [PRevent](https://github.com/apiiro/PRevent.git).

The rules are designed to run on comment-free code. As this is already handled by PRevent, comment filtering patterns were omitted for performance to avoid redundant processing. To avoid comments matching in other locations, simply add them.

A typical flow (and how PRevent is handling the Semgrep scan): 
1. Selecting a relevant scanning target (e.g. updated file).
2. Filtering relevant and irrelevant parts (e.g. remove comments).
3. Writing the result to a temporary file.
4. Scanning it.
5. Removing the temporary file when done.

If you're I/O bound before CPU bound, and your only processing is comments-removal, consider adding comment filtering to your rules instead of using temp files.

## Contributing

Contributions to improve the ruleset are welcome via pull requests or issues with new patterns (after comprehensive testing) or suggestions.

## License

This repository is licensed under the [MIT License](LICENSE).

---

For more information:  
https://apiiro.com/blog/guard-your-codebase-practical-steps-and-tools-to-prevent-malicious-code/
