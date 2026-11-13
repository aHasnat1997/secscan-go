package hostaudit

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

var procRe = regexp.MustCompile(`\(\("([^"]+)"`)

func splitHostPort(a string) (string, string) {
	i := strings.LastIndex(a, ":")
	if i < 0 {
		return a, ""
	}
	return a[:i], a[i+1:]
}

func isLoopback(h string) bool {
	return strings.HasPrefix(h, "127.") || h == "[::1]" || h == "::1"
}

// CheckListening inspects active TCP/UDP sockets listening on non-loopback interfaces.
func CheckListening(e *AuditEnv) ([]model.Finding, error) {
	out, _, _, err := runner.Run(e.Ctx, 15*time.Second, "ss", "-H", "-tulpn")
	if err != nil {
		return nil, err
	}

	allowed := map[string]bool{}
	for _, p := range e.Opts.Config.AllowedPorts {
		allowed[strconv.Itoa(p)] = true
	}

	type agg struct {
		sev model.Severity
		ev  []string
		pr  string
	}
	m := map[string]*agg{}
	var order []string

	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		host, port := splitHostPort(f[4])
		if isLoopback(host) || allowed[port] {
			continue
		}
		proc := ""
		if len(f) >= 7 {
			if g := procRe.FindStringSubmatch(f[6]); g != nil {
				proc = g[1]
			}
		}
		id := fmt.Sprintf("NET-LISTEN-%s-%s", f[0], port)
		if m[id] == nil {
			sev := model.SevMedium
			if f[0] == "udp" {
				sev = model.SevLow
			}
			m[id] = &agg{sev: sev, pr: proc}
			order = append(order, id)
		}
		m[id].ev = append(m[id].ev, fmt.Sprintf("%s %s  %s", f[0], f[4], proc))
	}

	var fs []model.Finding
	for _, id := range order {
		a := m[id]
		parts := strings.Split(id, "-")
		fix := "Stop/disable the service, bind it to 127.0.0.1, or block it in the firewall. If expected, add the port to allowed_ports in the config."
		if a.pr == "docker-proxy" {
			fix = "Publish to loopback only: -p 127.0.0.1:PORT:PORT (compose: \"127.0.0.1:PORT:PORT\"). Docker bypasses ufw, so the firewall does NOT protect this port."
		}
		fs = append(fs, finding(id, a.sev,
			fmt.Sprintf("Port %s/%s is reachable from the network (%s)", parts[3], parts[2], valOr(a.pr, "unknown process, run as root to see")),
			"Anything listening on a non-loopback address can be reached by other devices on your LAN.", fix, a.ev...))
	}
	return fs, nil
}

// CheckDocker inspects running Docker containers for ports published across all host interfaces.
func CheckDocker(e *AuditEnv) ([]model.Finding, error) {
	if !runner.Have("docker") {
		return nil, SkipError("docker not in use")
	}
	out, _, code, err := runner.Run(e.Ctx, 20*time.Second, "docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Ports}}")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, SkipError("docker daemon not reachable (not running or no permission)")
	}
	var ev []string
	for _, l := range lines(out) {
		if strings.Contains(l, "0.0.0.0:") || strings.Contains(l, ":::") {
			ev = append(ev, l)
		}
	}
	if len(ev) == 0 {
		return nil, nil
	}
	return []model.Finding{finding("NET-DOCKER-EXPOSED", model.SevMedium,
		fmt.Sprintf("%d running container(s) publish ports on all interfaces", len(ev)),
		"Docker writes its own iptables rules, so ufw rules do not apply to published ports.",
		"Use 127.0.0.1:HOST:CONTAINER in -p / compose ports, or put a reverse proxy in front.", ev...)}, nil
}

// CheckFirewall verifies that an active host-level firewall (ufw, nftables, or firewalld) is enforced.
func CheckFirewall(e *AuditEnv) ([]model.Finding, error) {
	var active []string
	for _, u := range []string{"ufw", "nftables", "firewalld"} {
		o, _, _, _ := runner.Run(e.Ctx, 5*time.Second, "systemctl", "is-active", u)
		if strings.TrimSpace(o) == "active" {
			active = append(active, u)
		}
	}
	if len(active) == 0 {
		return []model.Finding{finding("NET-FIREWALL", model.SevHigh, "No host firewall service is active", "",
			"sudo pacman -S ufw && sudo ufw default deny incoming && sudo ufw enable && sudo systemctl enable --now ufw")}, nil
	}
	if e.Root && runner.Have("ufw") && contains(active, "ufw") {
		o, _, _, _ := runner.Run(e.Ctx, 10*time.Second, "ufw", "status")
		if !strings.Contains(o, "Status: active") {
			return []model.Finding{finding("NET-FIREWALL", model.SevHigh, "ufw service runs but the firewall is not enabled",
				"ufw.service is active, yet `ufw status` reports inactive.", "sudo ufw enable", lines(o)...)}, nil
		}
	}
	return nil, nil
}

// CheckConnections audits established outbound internet connections to identify C2 channels,
// interpreters running hidden scripts, or stale/deleted unowned binaries.
func CheckConnections(e *AuditEnv) ([]model.Finding, error) {
	out, _, _, err := runner.Run(e.Ctx, 15*time.Second, "ss", "-H", "-tnp", "state", "established")
	if err != nil {
		return nil, err
	}

	type conn struct {
		name  string
		peers []string
	}
	by := map[string]*conn{}

	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		host, port := splitHostPort(f[3])
		host = strings.TrimPrefix(strings.Trim(host, "[]"), "::ffff:")
		ip := net.ParseIP(host)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		g := pidProcRe.FindStringSubmatch(f[4])
		if g == nil {
			continue
		}
		if by[g[2]] == nil {
			by[g[2]] = &conn{name: g[1]}
		}
		by[g[2]].peers = append(by[g[2]].peers, host+":"+port)
	}

	var pids []string
	for p := range by {
		pids = append(pids, p)
	}
	sort.Strings(pids)

	var hi, unpk, stale []string
	for _, pid := range pids {
		c := by[pid]
		exe, args := procInfo(pid)
		peers := c.peers
		if len(peers) > 3 {
			peers = peers[:3]
		}
		label := fmt.Sprintf("pid %s %s -> %s", pid, c.name, strings.Join(peers, ", "))
		deleted := strings.HasSuffix(exe, " (deleted)")
		exe = strings.TrimSuffix(exe, " (deleted)")

		switch {
		case exe == "":
			continue
		case strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/") || strings.HasPrefix(exe, "/dev/shm/"):
			hi = append(hi, label+" [binary in temp dir: "+exe+"]")
			continue
		}

		suspScript := ""
		if interpRe.MatchString(filepath.Base(exe)) {
			for _, a := range args[min(1, len(args)):] {
				if scriptDirRe.MatchString(a) && !legitScript.MatchString(a) {
					suspScript = a
					break
				}
			}
		}

		switch {
		case suspScript != "":
			why := "interpreter running " + suspScript
			if h := scanWithRefs(suspScript); h.bad() {
				why += "; " + h.why()
			}
			hi = append(hi, label+" ["+why+"]")
		case deleted && pacmanOwns(e, exe):
			stale = append(stale, label+" ["+exe+" was updated while running]")
		case deleted:
			hi = append(hi, label+" [binary deleted from disk and not owned by any package]")
		case !pacmanOwns(e, exe):
			unpk = append(unpk, fmt.Sprintf("%s [%s]", label, exe))
		}
	}

	var fs []model.Finding
	if len(hi) > 0 {
		fs = append(fs, finding("NET-OUTBOUND-SUSPICIOUS", model.SevHigh, fmt.Sprintf("%d suspicious processes hold connections to the internet", len(hi)),
			"Processes running from temp dirs, hidden script dirs, or deleted binaries that talk to external hosts are typical of command-and-control or exfiltration.",
			"Identify with ls -l /proc/<pid>/exe and sudo ss -tnp. Block the peer in the firewall, kill the process, remove its persistence.", hi...))
	}
	if len(unpk) > 0 {
		fs = append(fs, finding("NET-OUTBOUND-UNPACKAGED", model.SevLow, fmt.Sprintf("%d programs outside the package manager talk to the internet", len(unpk)),
			"Not malicious by itself (nvm node, AppImages, tools you built), but this is where unknown software shows up. Make sure you recognise each.",
			"Confirm each program is yours. Unknown ones: investigate, then remove.", unpk...))
	}
	if len(stale) > 0 {
		fs = append(fs, finding("NET-OUTBOUND-STALE", model.SevLow, fmt.Sprintf("%d connected programs run an outdated binary (package updated since launch)", len(stale)),
			"The packaged program was upgraded while still running, so the old, possibly vulnerable version stays in memory.", "Restart those apps or reboot.", stale...))
	}
	if !e.Root {
		fs = append(fs, finding("NET-PARTIAL", model.SevInfo, "Connection scan limited to your own processes", "", "Run with sudo for full coverage."))
	}
	return fs, nil
}

