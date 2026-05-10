// Package dockerfile provides Dockerfile parsing and base-image analysis.
// Mirrors lib/dockerfile/ (index.ts + instruction-parser.ts).
package dockerfile

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ReadDockerfileAndAnalyse reads the Dockerfile at path and returns an
// analysis. Returns nil, nil when path is empty.
func ReadDockerfileAndAnalyse(path string) (*DockerfileAnalysis, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	a := AnalyseDockerfile(string(data))
	return &a, nil
}

// AnalyseDockerfile parses Dockerfile text and returns the analysis.
// Mirrors lib/dockerfile/index.ts analyseDockerfile().
func AnalyseDockerfile(contents string) DockerfileAnalysis {
	lines := splitLines(contents)
	argDefs := parseArgDefs(lines)

	froms := collectFroms(lines, argDefs)
	baseImageResult := resolveBaseImage(froms, argDefs)

	runInstructions := collectRunInstructions(lines, argDefs)
	pkgs := getPackagesFromRunInstructions(runInstructions)
	layers := getLayersFromPackages(pkgs)

	return DockerfileAnalysis{
		BaseImage:          baseImageResult.baseImage,
		DockerfilePackages: pkgs,
		DockerfileLayers:   layers,
		Error:              baseImageResult.err,
	}
}

// InstructionDigest returns the base64 encoding of an instruction string.
// Mirrors lib/dockerfile/instruction-parser.ts instructionDigest().
func InstructionDigest(instruction string) string {
	return base64.StdEncoding.EncodeToString([]byte(instruction))
}

// GetLayersFromPackages builds the DockerfileLayers map from packages.
// Mirrors lib/dockerfile/instruction-parser.ts getLayersFromPackages().
func getLayersFromPackages(pkgs DockerfilePackages) DockerfileLayers {
	layers := make(DockerfileLayers)
	for _, p := range pkgs {
		digest := InstructionDigest(p.Instruction)
		layers[digest] = LayerInstruction{Instruction: p.Instruction}
	}
	return layers
}

// ---------------------------------------------------------------------------
// ARG resolution
// ---------------------------------------------------------------------------

// parseArgDefs scans for ARG name=default lines and returns the map.
// Quoted values like ARG FOO="bar baz" are stripped of their outer quotes.
func parseArgDefs(lines []string) map[string]string {
	args := map[string]string{}
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if !instructionIs(trim, "ARG") {
			continue
		}
		body := strings.TrimSpace(trim[3:])
		if idx := strings.IndexByte(body, '='); idx >= 0 {
			val := body[idx+1:]
			// Strip surrounding quotes (both single and double).
			val = strings.Trim(val, `"'`)
			args[body[:idx]] = val
		} else {
			args[body] = ""
		}
	}
	return args
}

// expandVars replaces ${VAR} and $VAR in text using the provided defs.
// Returns ("", false) if any referenced variable has no definition at all
// (unresolvable), otherwise returns (expanded, true).
func expandVars(text string, defs map[string]string) (string, bool) {
	out := text

	// ${VAR} form
	braceRE := regexp.MustCompile(`\$\{([^}]+)\}`)
	all := braceRE.FindAllStringSubmatchIndex(out, -1)
	for i := len(all) - 1; i >= 0; i-- {
		m := all[i]
		name := out[m[2]:m[3]]
		val, ok := defs[name]
		if !ok {
			return "", false
		}
		out = out[:m[0]] + val + out[m[1]:]
	}

	// $VAR form (word boundary)
	plainRE := regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	all = plainRE.FindAllStringSubmatchIndex(out, -1)
	for i := len(all) - 1; i >= 0; i-- {
		m := all[i]
		name := out[m[2]:m[3]]
		val, ok := defs[name]
		if !ok {
			return "", false
		}
		out = out[:m[0]] + val + out[m[1]:]
	}

	return out, true
}

// hasUnresolvedVars returns true when ${VAR} or $VAR remain in text.
func hasUnresolvedVars(text string) bool {
	return strings.Contains(text, "$")
}

// ---------------------------------------------------------------------------
// FROM instruction handling
// ---------------------------------------------------------------------------

type fromEntry struct {
	image string // raw image string after FROM
	alias string // AS alias, if any
}

type baseImageResult struct {
	baseImage string
	err       *AnalysisError
}

// collectFroms returns all FROM instructions, with variables expanded.
func collectFroms(lines []string, argDefs map[string]string) []fromEntry {
	var result []fromEntry
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if !instructionIs(trim, "FROM") {
			continue
		}
		body := strings.TrimSpace(trim[4:])
		// Remove inline comment
		if idx := strings.Index(body, " #"); idx >= 0 {
			body = strings.TrimSpace(body[:idx])
		}
		parts := strings.Fields(body)
		if len(parts) == 0 {
			continue
		}
		image := parts[0]
		alias := ""
		if len(parts) >= 3 && strings.EqualFold(parts[1], "AS") {
			alias = parts[2]
		}
		// Expand variables in the image name
		expanded, ok := expandVars(image, argDefs)
		if ok {
			image = expanded
		} else {
			image = "" // mark as unresolvable
		}
		result = append(result, fromEntry{image: image, alias: alias})
	}
	return result
}

// resolveBaseImage mirrors getDockerfileBaseImageName() from instruction-parser.ts.
// It resolves aliases and returns the final stage's base image.
func resolveBaseImage(froms []fromEntry, argDefs map[string]string) baseImageResult {
	if len(froms) == 0 {
		return baseImageResult{err: &AnalysisError{Code: ErrBaseImageNotFound}}
	}

	// Build alias map: alias → resolved image name.
	aliases := map[string]string{}
	var lastImage string
	resolvable := true

	for _, f := range froms {
		img := f.image

		// Resolve alias reference
		if resolved, ok := aliases[img]; ok {
			img = resolved
		}

		// Detect remaining variables after expansion
		if img == "" || hasUnresolvedVars(img) {
			resolvable = false
			lastImage = ""
			if f.alias != "" {
				aliases[f.alias] = ""
			}
			continue
		}

		// Detect partial resolution: tag or digest part is empty
		if hasEmptySegment(img) {
			resolvable = false
			lastImage = ""
			if f.alias != "" {
				aliases[f.alias] = ""
			}
			continue
		}

		lastImage = img
		resolvable = true
		if f.alias != "" {
			aliases[f.alias] = img
		}
	}

	if lastImage == "" {
		if !resolvable {
			return baseImageResult{err: &AnalysisError{Code: ErrBaseImageNonResolvable}}
		}
		return baseImageResult{err: &AnalysisError{Code: ErrBaseImageNotFound}}
	}
	return baseImageResult{baseImage: lastImage}
}

// hasEmptySegment detects patterns where the name or tag segment is empty:
// "image:" (trailing colon), ":tag" (missing name), "image@" (trailing @),
// or "@digest" (missing name). These indicate unresolvable variable expansion.
func hasEmptySegment(img string) bool {
	if img == "" {
		return true
	}
	if idx := strings.Index(img, ":"); idx >= 0 {
		// Empty name (leading colon) or empty tag (trailing colon).
		if idx == 0 || idx == len(img)-1 {
			return true
		}
	}
	if idx := strings.Index(img, "@"); idx >= 0 {
		// Empty name (leading @) or empty digest (trailing @).
		if idx == 0 || idx == len(img)-1 {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// RUN instruction / package extraction
// ---------------------------------------------------------------------------

// installRegex mirrors the TS installRegex exactly.
var installRegex = regexp.MustCompile(
	`(rpm\s+-i|rpm\s+--install|` +
		`apk\s+((--update|-u|--no-cache)\s+)*add(\s+(--update|-u|--no-cache))*|` +
		`apt-get\s+((--assume-yes|--yes|-y)\s+)*install(\s+(--assume-yes|--yes|-y))*|` +
		`apt\s+((--assume-yes|--yes|-y)\s+)*install|` +
		`dnf\s+((--assumeyes|--best|--nodocs|--allowerasing|-y)\s+)*install(\s+(--assumeyes|--best|--nodocs|--allowerasing|-y))*|` +
		`microdnf\s+((--nodocs|--best|--assumeyes|-y)\s+)*install(\s+(--nodocs|--best|--assumeyes|-y))*|` +
		`yum\s+install|` +
		`aptitude\s+install)\s+`,
)

// collectRunInstructions returns the text of each RUN instruction.
// Continuation lines (ending in \) are joined. Variables are expanded.
func collectRunInstructions(lines []string, argDefs map[string]string) []string {
	var result []string
	var current strings.Builder
	inRun := false

	for _, raw := range lines {
		line := raw
		trim := strings.TrimSpace(line)

		if !inRun {
			if !instructionIs(trim, "RUN") {
				continue
			}
			current.Reset()
			// body after RUN keyword
			body := strings.TrimSpace(trim[3:])
			if strings.HasSuffix(body, "\\") {
				current.WriteString(strings.TrimSuffix(body, "\\"))
				inRun = true
			} else {
				result = append(result, expandInstruction("RUN "+body, argDefs))
			}
		} else {
			if strings.HasSuffix(trim, "\\") {
				current.WriteString(" ")
				current.WriteString(strings.TrimSuffix(trim, "\\"))
			} else {
				current.WriteString(" ")
				current.WriteString(trim)
				result = append(result, expandInstruction("RUN "+strings.TrimSpace(current.String()), argDefs))
				inRun = false
			}
		}
	}
	if inRun && current.Len() > 0 {
		result = append(result, expandInstruction("RUN "+strings.TrimSpace(current.String()), argDefs))
	}
	return result
}

func expandInstruction(instr string, argDefs map[string]string) string {
	expanded, ok := expandVars(instr, argDefs)
	if ok {
		return expanded
	}
	return instr
}

// getPackagesFromRunInstructions mirrors the TS function of the same name.
// It returns a DockerfilePackages map from all RUN instructions.
func getPackagesFromRunInstructions(runInstructions []string) DockerfilePackages {
	pkgs := make(DockerfilePackages)
	for _, instruction := range runInstructions {
		clean := cleanInstruction(instruction)
		commands := splitCommands(clean)
		installCmds := filterInstallCommands(commands)
		for _, cmd := range installCmds {
			// Strip the install prefix to get bare package arguments
			pkgStr := installRegex.ReplaceAllString(cmd, "")
			for _, pkg := range strings.Fields(pkgStr) {
				if pkg == "" || strings.HasPrefix(pkg, "-") {
					continue
				}
				// Strip version specifier (foo=1.2)
				name := strings.SplitN(pkg, "=", 2)[0]
				// Strip leading $ (unresolved var)
				if strings.HasPrefix(name, "$") {
					name = name[1:]
				}
				installCmd := findInstallCmd(installCmds, name)
				pkgs[name] = PackageInstall{
					Instruction:    instruction,
					InstallCommand: installCmd,
				}
			}
		}
	}
	return pkgs
}

// cleanInstruction strips leading RUN / /bin/sh -c prefixes.
// Mirrors cleanInstruction() from instruction-parser.ts.
func cleanInstruction(instruction string) string {
	s := instruction
	runDefs := []string{"RUN ", "/bin/sh ", "-c "}
	argsPrefixRE := regexp.MustCompile(`^\|\d .*?=`)
	for _, prefix := range runDefs {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			if prefix == "RUN " && argsPrefixRE.MatchString(s) {
				if loc := installRegex.FindStringIndex(s); loc != nil {
					s = s[loc[0]:]
				}
			}
		}
	}
	return s
}

// splitCommands splits on ; or && separators.
func splitCommands(s string) []string {
	re := regexp.MustCompile(`\s?(;|&&)\s?`)
	return re.Split(s, -1)
}

func filterInstallCommands(cmds []string) []string {
	var out []string
	for _, c := range cmds {
		if installRegex.MatchString(c) {
			out = append(out, c)
		}
	}
	return out
}

func findInstallCmd(installCmds []string, pkg string) string {
	for _, cmd := range installCmds {
		if strings.Contains(cmd, pkg) {
			return strings.Join(strings.Fields(cmd), " ")
		}
	}
	return "Unknown"
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// instructionIs checks whether a trimmed line starts with the given keyword
// (case-insensitive) followed by a space or end of string.
func instructionIs(line, kw string) bool {
	upper := strings.ToUpper(line)
	if !strings.HasPrefix(upper, kw) {
		return false
	}
	rest := line[len(kw):]
	return rest == "" || rest[0] == ' ' || rest[0] == '\t'
}

// splitLines splits text on \n, stripping \r.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}
