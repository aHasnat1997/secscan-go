package codescan

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"

	"security-go-scanner/src/model"
)

// Rule defines a single-line static pattern matching signature for malware or risk indicators.
type Rule struct {
	ID       string
	Category string
	Severity model.Severity
	Pattern  *regexp.Regexp
	Why      string
}

// CooccurRule defines a multi-pattern heuristic where all sub-patterns must appear within the same file.
type CooccurRule struct {
	ID       string
	Category string
	Severity model.Severity
	Patterns []*regexp.Regexp
	Why      string
}

var (
	rulesOnce    sync.Once
	codeRules    []Rule
	cooccurRules []CooccurRule
)

// initRules compiles all regex and co-occurrence rules safely once.
func initRules() {
	rulesOnce.Do(func() {
		compileRule := func(id, cat string, sev model.Severity, pattern, why string, caseInsensitive bool) Rule {
			flags := ""
			if caseInsensitive {
				flags = "(?i)"
			}
			return Rule{
				ID:       id,
				Category: cat,
				Severity: sev,
				Pattern:  regexp.MustCompile(flags + pattern),
				Why:      why,
			}
		}

		codeRules = []Rule{
			// --- Reverse shells ---
			compileRule("rs-bash-devtcp", "reverse_shell", model.SevCritical, `/dev/(tcp|udp)/[\w.\-$\{\}]+/\d+`, "bash /dev/tcp socket redirection, classic reverse-shell primitive", true),
			compileRule("rs-bash-i", "reverse_shell", model.SevHigh, `\bbash\s+-i\s*>&|\bsh\s+-i\s*[<>]&`, "interactive shell redirected to a socket", false),
			compileRule("rs-nc-exec", "reverse_shell", model.SevHigh, `\b(nc|ncat|netcat)\b[^\n]{0,60}\s-(e|c)\s+\S*(sh|bash|cmd)`, "netcat executing a shell", true),
			compileRule("rs-mkfifo-nc", "reverse_shell", model.SevHigh, `mkfifo\s+\S+[^\n]{0,120}\b(nc|ncat|netcat)\b`, "named-pipe + netcat reverse-shell pattern", false),
			compileRule("rs-pty-spawn", "reverse_shell", model.SevMedium, `\bpty\.spawn\s*\(\s*['"]?/?(bin/)?(ba)?sh`, "pty.spawn of a shell (often used after a socket connect)", false),
			compileRule("rs-ps-tcpclient", "reverse_shell", model.SevHigh, `System\.Net\.Sockets\.TCPClient`, "PowerShell TCPClient, common in reverse shells", false),
			compileRule("rs-socat-exec", "reverse_shell", model.SevHigh, `\bsocat\b[^\n]{0,80}(EXEC|exec):`, "socat exec: relay to a shell", false),
			compileRule("rs-php-fsockopen", "reverse_shell", model.SevMedium, `fsockopen\s*\([^\n]{0,80}\)[^\n]{0,200}(proc_open|shell_exec|exec|system)\s*\(`, "PHP socket + command execution", false),

			// --- Crypto clipboard hijack ---
			compileRule("addr-regex-swap", "clipboard_hijack", model.SevHigh, `(\^?0x\[a-fA-F0-9\]\{40\}|bc1\[|\[13\]\[a-km-zA-HJ-NP-Z1-9\]\{25,34\}|\[a-km-zA-HJ-NP-Z1-9\]\{25,34\})`, "regex that recognises crypto addresses (used to detect-and-replace clipboard content)", false),
			compileRule("clip-poll", "clipboard_hijack", model.SevMedium, `(setInterval|setTimeout|while\s+True|for\s*\(\s*;;\s*\)|time\.sleep|Sleep\()[^\n]{0,160}(clipboard|pbpaste|xclip|pyperclip)`, "clipboard polled in a timer/loop", false),

			// --- Rootkit / stealth ---
			compileRule("rk-ld-preload-file", "rootkit", model.SevHigh, `/etc/ld\.so\.preload`, "touches the global preload list used by userland rootkits", false),
			compileRule("rk-ld-preload-env", "rootkit", model.SevMedium, `\bLD_(PRELOAD|AUDIT|LIBRARY_PATH)\s*=`, "LD_PRELOAD-style library injection", false),
			compileRule("rk-dlsym-next", "rootkit", model.SevMedium, `dlsym\s*\(\s*RTLD_NEXT`, "libc function interposition (hooking)", false),
			compileRule("rk-syscall-table", "rootkit", model.SevCritical, `\bsys_call_table\b`, "kernel syscall table access (syscall hooking)", false),
			compileRule("rk-kallsyms", "rootkit", model.SevHigh, `kallsyms_lookup_name|kprobe_lookup|register_kprobe`, "kernel symbol lookup/kprobe, used to hook kernel functions", false),
			compileRule("rk-ftrace-hook", "rootkit", model.SevHigh, `ftrace_set_filter_ip|register_ftrace_function`, "ftrace-based kernel function hooking", false),
			compileRule("rk-kmod-src", "rootkit", model.SevMedium, `\bMODULE_LICENSE\s*\(|\bmodule_init\s*\(|\bmodule_exit\s*\(`, "Linux kernel module source (legit drivers exist; review purpose)", false),
			compileRule("rk-kmod-load", "rootkit", model.SevMedium, `\b(insmod|modprobe|finit_module|init_module)\b`, "loads a kernel module", false),
			compileRule("rk-hide-proc", "rootkit", model.SevHigh, `(hide_pid|hide_proc|hide_file|hidden_pids|filldir|getdents64?)\s*[\(=]`, "process/file hiding or directory-listing hook", false),
			compileRule("rk-devmem", "rootkit", model.SevHigh, `/dev/(k?mem|port)\b`, "raw kernel/physical memory access", false),
			compileRule("rk-ptrace-inject", "rootkit", model.SevMedium, `PTRACE_(POKETEXT|POKEDATA|ATTACH|SEIZE)`, "ptrace memory write/attach (process injection)", false),
			compileRule("rk-bpf-write", "rootkit", model.SevHigh, `bpf_probe_write_user|bpf_override_return`, "eBPF helpers abused by eBPF rootkits", false),
			compileRule("rk-pam-backdoor", "rootkit", model.SevHigh, `pam_sm_authenticate|pam_get_authtok`, "PAM module code (can implement credential backdoors)", false),
			compileRule("rk-immutable", "rootkit", model.SevMedium, `\bchattr\s+\+[ia]\b`, "makes files immutable (persistence/anti-removal)", false),

			// --- Persistence ---
			compileRule("per-authkeys", "persistence", model.SevHigh, `(>>?|tee\s+-a|append|write)[^\n]{0,60}authorized_keys|authorized_keys[^\n]{0,60}(>>|echo|printf)`, "writes to SSH authorized_keys", false),
			compileRule("per-cron", "persistence", model.SevMedium, `(crontab\s+-|/etc/cron\.|/var/spool/cron|\(crontab\s+-l)`, "installs cron jobs", false),
			compileRule("per-shellrc", "persistence", model.SevMedium, `(>>|tee\s+-a)\s*[~$\w/\{\}\"']*\.(bashrc|zshrc|profile|bash_profile)`, "appends to shell startup files", false),
			compileRule("per-systemd", "persistence", model.SevMedium, `/etc/systemd/system/|systemctl\s+enable|/Library/Launch(Agents|Daemons)`, "installs a service/launch agent", false),
			compileRule("per-winrun", "persistence", model.SevMedium, `CurrentVersion\\Run|schtasks\s+/create|Start Menu\\Programs\\Startup`, "Windows autorun persistence", false),

			// --- Obfuscation / loaders ---
			compileRule("obf-eval-b64", "obfuscation", model.SevHigh, `(eval|exec|Function)\s*\(\s*[^\n]{0,60}(atob|b64decode|base64\.|Buffer\.from\([^\n]{0,80}base64|decompress|fromCharCode)`, "decodes data and executes it", false),
			compileRule("obf-py-exec-compile", "obfuscation", model.SevHigh, `exec\s*\(\s*(compile|marshal\.loads|zlib\.decompress|base64\.b64decode)`, "Python exec of decoded/compiled payload", false),
			compileRule("obf-ps-encoded", "obfuscation", model.SevHigh, `-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|FromBase64String\s*\([^\n]{0,80}\)[^\n]{0,80}(IEX|Invoke-Expression)`, "PowerShell encoded command", true),
			compileRule("obf-dl-exec", "obfuscation", model.SevHigh, `(curl|wget)\s+[^\n|;]{0,160}\|\s*(sudo\s+)?(ba|z|da)?sh\b`, "download piped straight into a shell", false),
			compileRule("obf-long-b64", "obfuscation", model.SevLow, `[A-Za-z0-9+/]{400,}={0,2}`, "very long base64-like blob (packed payload or embedded asset)", false),
			compileRule("obf-hex-array", "obfuscation", model.SevMedium, `(\\x[0-9a-fA-F]{2}){40,}`, "long hex-escaped string (shellcode or hidden strings)", false),
			compileRule("obf-js-array", "obfuscation", model.SevMedium, `_0x[0-9a-f]{4,6}\s*\(`, "javascript-obfuscator style identifiers", false),

			// --- Exfiltration / credential theft ---
			compileRule("ex-discord-hook", "exfiltration", model.SevHigh, `discord(app)?\.com/api/webhooks/\d+/`, "Discord webhook (common stealer exfil channel)", false),
			compileRule("ex-telegram-bot", "exfiltration", model.SevHigh, `api\.telegram\.org/bot[\w:\-]+/(sendMessage|sendDocument)`, "Telegram bot API (common stealer exfil channel)", false),
			compileRule("ex-wallet-files", "exfiltration", model.SevHigh, `(wallet\.dat|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|Exodus[\\/]exodus\.wallet|Electrum[\\/]wallets|keystore[\\/]UTC--)`, "reads crypto-wallet or wallet-extension storage", false),
			compileRule("ex-browser-creds", "exfiltration", model.SevHigh, `(Login Data|Web Data|logins\.json|key4\.db|Cookies\.sqlite)[\"'\s)]`, "reads browser credential stores", false),
			compileRule("ex-ssh-keys", "exfiltration", model.SevMedium, `(\.ssh[\\/]id_(rsa|ed25519|ecdsa)|\.aws[\\/]credentials|\.kube[\\/]config|\.npmrc|\.git-credentials)`, "touches private keys / cloud credentials", true),
			compileRule("ex-seed-phrase", "exfiltration", model.SevMedium, `(seed\s*phrase|mnemonic|private\s*key)[^\n]{0,80}(fetch|axios|requests\.post|http\.request|curl|upload|send)`, "seed/private key near a network send", false),

			// --- Miners ---
			compileRule("min-stratum", "miner", model.SevHigh, `stratum\+(tcp|ssl)://|\bxmrig\b|\bcryptonight\b|coinhive|minergate|\brandomx\b`, "cryptocurrency miner indicators", true),
		}

		compileCooccur := func(id, cat string, sev model.Severity, patterns []string, why string) CooccurRule {
			var rxs []*regexp.Regexp
			for _, p := range patterns {
				rxs = append(rxs, regexp.MustCompile(p))
			}
			return CooccurRule{ID: id, Category: cat, Severity: sev, Patterns: rxs, Why: why}
		}

		cooccurRules = []CooccurRule{
			compileCooccur("rs-py-socket-shell", "reverse_shell", model.SevCritical,
				[]string{`\bsocket\.socket\s*\(`, `\.connect\s*\(`, `(os\.dup2|pty\.spawn|subprocess\.(Popen|call|run)|os\.(system|execv))`},
				"Python socket connect wired to a shell"),
			compileCooccur("rs-node-socket-shell", "reverse_shell", model.SevCritical,
				[]string{`(require\(['"]net['"]\)|from ['"]net['"]|net\.(Socket|connect|createConnection))`, `child_process|\bspawn\s*\(|\bexec(Sync)?\s*\(`, `['"](/bin/)?(ba)?sh['"]|cmd\.exe|powershell`},
				"Node net socket piped to a shell process"),
			compileCooccur("rs-go-dial-shell", "reverse_shell", model.SevHigh,
				[]string{`net\.Dial\s*\(`, `exec\.Command\s*\(\s*"(/bin/)?(ba)?sh"|cmd\.exe`},
				"Go network dial + shell exec"),
			compileCooccur("rs-perl-ruby-socket", "reverse_shell", model.SevHigh,
				[]string{`(TCPSocket\.(new|open)|IO\.popen|Socket\.(new|INET)|socket\s*\(\s*S)`, `(exec\s*[\("']|system\s*\(|spawn\s*\(|STDIN\.reopen|open\s*\(\s*STDIN)`},
				"Ruby/Perl socket wired to a shell"),
			compileCooccur("clip-hijack-combo", "clipboard_hijack", model.SevCritical,
				[]string{
					`(navigator\.clipboard|clipboardy|pyperclip|pbpaste|xclip|wl-paste|GetClipboardData|win32clipboard|Clipboard\.(Get|Set)Text|clipboard\.(read|write)\()`,
					`(0x\[a-fA-F0-9\]\{40\}|bc1|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|\b0x[a-fA-F0-9]{40}\b|\b(bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b)`,
					`(replace|writeText|writeSync|\w+\.write\(|\.copy\(|SetText|SetClipboardData|clipboard_set|clipboard\.write)`,
				},
				"clipboard read + crypto-address match + clipboard write: address-swapping hijacker pattern"),
		}
	})
}

var (
	binaryMagic = map[string]string{
		"\x7fELF":          "ELF executable/library",
		"MZ":               "Windows PE executable",
		"\xcf\xfa\xed\xfe": "Mach-O executable (32-bit)",
		"\xfe\xed\xfa\xcf": "Mach-O executable (32-bit swap)",
		"\xcf\xfa\xed\xff": "Mach-O executable (64-bit)",
		"\xfe\xed\xfa\xce": "Mach-O executable (64-bit swap)",
		"\xca\xfe\xba\xbe": "Mach-O universal binary / Java class",
	}

	binaryExts = map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".ko": true,
		".dylib": true, ".scr": true, ".sys": true, ".node": true,
		".bin": true, ".msi": true, ".com": true,
	}

	windowsScriptExts = map[string]bool{
		".bat": true, ".cmd": true, ".vbs": true,
		".ps1": true, ".hta": true, ".jse": true, ".wsf": true,
	}

	doubleExtRe    = regexp.MustCompile(`(?i)\.(pdf|jpe?g|png|gif|txt|docx?|xlsx?)\.(exe|scr|bat|cmd|js|vbs|ps1)$`)
	bidiRe         = regexp.MustCompile("[\u202a-\u202e\u2066-\u2069]")
	riskyScriptRe  = regexp.MustCompile(`(?i)(curl|wget|\bsh\b|bash|node\s+-e|powershell|eval|base64|nc\s|/dev/tcp)`)
	npmLifecycleRe = map[string]bool{"preinstall": true, "install": true, "postinstall": true, "prepare": true, "prepublish": true}
)

func sha256Bytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// formatSnippet normalizes a line of source code for safe terminal and JSON reporting,
// stripping non-printable control characters and bounding length to 200 characters.
func formatSnippet(s string) string {
	s = strings.TrimSpace(s)
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('?')
		}
	}
	res := sb.String()
	if len(res) > 200 {
		return res[:200] + "..."
	}
	return res
}

