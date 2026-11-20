# frozen_string_literal: true

module Gargoyle
  # One detection rule. `targets` says which parts of the request it looks at.
  Rule = Struct.new(:id, :title, :severity, :targets, :pattern, :owasp, :attack, keyword_init: true)

  SEVERITY = { low: 1, medium: 2, high: 3 }.freeze

  # Patterns are deliberately simple and bounded: they run on attacker-controlled text. Input is cut to
  # Detector::MAX_SCAN characters before matching, and no pattern nests unbounded quantifiers.
  RULES = [
    Rule.new(id: "scanner-ua", title: "Known scanner or attack tool in User-Agent", severity: :low, targets: [:ua],
             pattern: /(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|wpscan|gobuster|dirbuster|ffuf|feroxbuster|burpsuite|havij|nessus|openvas)/i,
             owasp: "A05", attack: "T1595.002"),
    Rule.new(id: "sensitive-path", title: "Probe for a file or admin page that should not be public", severity: :medium, targets: [:path],
             pattern: %r{/(\.env|\.git/|\.svn/|\.aws/|\.ds_store|\.htpasswd|wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|actuator|server-status|id_rsa|backup\.(zip|sql|tar)|config\.(php|json|yml))}i,
             owasp: "A05", attack: "T1595.003"),
    Rule.new(id: "path-traversal", title: "Path traversal sequence", severity: :high, targets: %i[path query body],
             pattern: %r{(\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|%252e%252e)}i, owasp: "A01", attack: "T1190"),
    Rule.new(id: "sql-injection", title: "SQL injection pattern", severity: :high, targets: %i[query body],
             pattern: /(\bunion(\s|\/\*[^*]{0,20}\*\/)+(all(\s|\/\*[^*]{0,20}\*\/)+)?select\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|information_schema|\bdrop\s+table\b)/i,
             owasp: "A03", attack: "T1190"),
    Rule.new(id: "xss", title: "Script injection pattern", severity: :medium, targets: %i[query body],
             pattern: /(<script\b|javascript:|\bonerror\s*=|\bonload\s*=)/i, owasp: "A03", attack: "T1190"),
    Rule.new(id: "command-injection", title: "Shell command injection pattern", severity: :high, targets: %i[query body],
             pattern: /(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b/i, owasp: "A03", attack: "T1190"),
    Rule.new(id: "log4shell", title: "JNDI lookup string (Log4Shell)", severity: :high, targets: %i[path query body headers ua],
             pattern: /\$\{\s*jndi\s*:/i, owasp: "A06", attack: "T1190"),
    Rule.new(id: "shellshock", title: "Function definition in a header (Shellshock)", severity: :high, targets: %i[headers ua],
             pattern: /\(\)\s*\{/, owasp: "A06", attack: "T1190"),
    Rule.new(id: "ssrf-metadata", title: "Request aimed at a cloud metadata address", severity: :high, targets: %i[query body],
             pattern: /(169\.254\.169\.254|metadata\.google\.internal)/i, owasp: "A10", attack: "T1190"),
    Rule.new(id: "prompt-injection", title: "Instruction-override phrase aimed at an LLM", severity: :medium, targets: %i[query body],
             pattern: /(ignore (all )?(the )?(previous|prior|above) instructions|disregard (your|the) (system )?prompt|you are now (in )?(dan|developer mode))/i,
             owasp: "LLM01", attack: "T1190")
  ].freeze
end
