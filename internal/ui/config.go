package ui

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
)

const maxYAML = 512 << 10

type configData struct {
	Current     int
	Selected    int // generation shown in the editor
	YAML        string
	Generations []core.ConfigGeneration
	// Result of Validate or a refused Activate; nil otherwise.
	Check *core.ConfigCheck
	// Action says what produced Check: "validate" or "activate".
	Action     string
	LDAPActive bool
}

func (h *Handler) configPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	cfg := h.Config.Current()
	sel := cfg.Generation
	if g, err := strconv.Atoi(r.URL.Query().Get("gen")); err == nil && g > 0 {
		sel = g
	}
	data, err := h.Admin.Read(r.Context(), sel)
	if err != nil {
		if isNotFound(err) {
			h.redirect(w, r, base+"/admin/config", "error", fmt.Sprintf("Generation %d does not exist.", sel))
			return
		}
		h.serverError(w, r, cur, "read configuration", err)
		return
	}
	h.renderConfig(w, r, cur, http.StatusOK, sel, string(data), nil, "")
}

func (h *Handler) renderConfig(w http.ResponseWriter, r *http.Request, cur *auth.Current, status, sel int, yaml string, check *core.ConfigCheck, action string) {
	gens, err := h.Admin.Generations(r.Context())
	if err != nil {
		h.serverError(w, r, cur, "list generations", err)
		return
	}
	cfg := h.Config.Current()
	d := &configData{Current: cfg.Generation, Selected: sel, YAML: yaml, Generations: gens, Check: check, Action: action, LDAPActive: cfg.LDAP.URL != ""}
	h.render(w, status, "admin_config", h.newPage(w, r, cur, "Configuration", "admin-config", d))
}

// formYAML reads the editor's YAML. It bounds the body itself (the CSRF
// middleware's cap does not apply when the token travels in a header) and
// has answered the request when it returns false.
func (h *Handler) formYAML(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !limitForm(w, r, maxYAML+maxForm) {
		return "", false
	}
	y := r.PostFormValue("yaml")
	if len(y) > maxYAML {
		http.Error(w, "configuration too large", http.StatusRequestEntityTooLarge)
		return "", false
	}
	return strings.ReplaceAll(y, "\r\n", "\n"), true
}

func (h *Handler) configValidate(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	yaml, ok := h.formYAML(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	check, err := h.Admin.Validate(ctx, []byte(yaml))
	if err != nil {
		h.serverError(w, r, cur, "validate configuration", err)
		return
	}
	h.renderConfig(w, r, cur, http.StatusOK, selectedGen(r, h.Config.Current().Generation), yaml, &check, "validate")
}

func selectedGen(r *http.Request, def int) int {
	if g, err := strconv.Atoi(r.PostFormValue("gen")); err == nil && g > 0 {
		return g
	}
	return def
}

func (h *Handler) configActivate(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	yaml, ok := h.formYAML(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	n, check, err := h.Admin.Activate(ctx, []byte(yaml))
	if err != nil {
		h.serverError(w, r, cur, "activate configuration", err)
		return
	}
	if !check.OK() {
		h.renderConfig(w, r, cur, http.StatusUnprocessableEntity, selectedGen(r, h.Config.Current().Generation), yaml, &check, "activate")
		return
	}
	h.record(r, cur, core.AuditConfigChange, fmt.Sprintf("activated generation %d", n), 0)
	msg := fmt.Sprintf("Generation %d is now active.", n)
	kind := "ok"
	if len(check.Warnings) > 0 {
		kind = "warn"
		msg += " Warnings: " + strings.Join(check.Warnings, "; ")
	}
	h.redirect(w, r, base+"/admin/config", kind, msg)
}

func (h *Handler) configRollback(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if !limitForm(w, r, maxForm) {
		return
	}
	n, err := strconv.Atoi(r.PostFormValue("gen"))
	if err != nil || n <= 0 {
		h.redirect(w, r, base+"/admin/config", "error", "Choose a generation to roll back to.")
		return
	}
	if err := h.Admin.Rollback(r.Context(), n); err != nil {
		if isNotFound(err) {
			h.redirect(w, r, base+"/admin/config", "error", fmt.Sprintf("Generation %d does not exist.", n))
			return
		}
		// A generation that no longer validates is an operator-facing
		// message, not an internal fault.
		h.Logger.Warn("ui: rollback refused", "generation", n, "error", err)
		h.redirect(w, r, base+"/admin/config", "error", fmt.Sprintf("Rollback to generation %d failed: %v", n, err))
		return
	}
	h.record(r, cur, core.AuditConfigChange, fmt.Sprintf("rolled back to generation %d", n), 0)
	h.redirect(w, r, base+"/admin/config", "ok", fmt.Sprintf("Rolled back: the content of generation %d is active again.", n))
}

func (h *Handler) configTestLDAP(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	back := base + "/admin/config"
	cfg := h.Config.Current()
	if cfg.LDAP.URL == "" {
		h.redirect(w, r, back, "error", "LDAP is not configured in the active generation.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	err := h.LDAP.TestLDAP(ctx, cfg.LDAP)
	h.recordLDAPTest(err)
	if err != nil {
		h.Auditor.Record(r.Context(), core.AuditEvent{
			Time: h.Clock.Now(), Type: core.AuditError, Visibility: core.AuditVisibilityAdmin, Mode: core.ModeUI,
			SourceIP: sourceIP(r).String(), Username: cur.User.Username, Result: core.AuditResultFailed, Detail: "LDAP test failed: " + err.Error(),
		})
		h.redirect(w, r, back, "error", "LDAP test failed: "+err.Error())
		return
	}
	h.redirect(w, r, back, "ok", "LDAP test succeeded: connect, service bind and user filter work.")
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

var secretNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

const maxSecret = 64 << 10

type secretRef struct {
	Name   string
	Where  string
	Exists bool
}

type secretsData struct {
	Names    []string
	Refs     []secretRef
	Missing  int
	Reserved map[string]bool
}

// secretRefs lists the secret names the active configuration refers to.
func secretRefs(cfg *core.Config, have []string) []secretRef {
	var refs []secretRef
	add := func(where, name string) {
		if name != "" {
			refs = append(refs, secretRef{Name: name, Where: where, Exists: slices.Contains(have, name)})
		}
	}
	add("route53.access_key_id_secret", cfg.Route53.AccessKeyIDSecret)
	add("route53.secret_access_key_secret", cfg.Route53.SecretAccessKeySecret)
	for i, p := range cfg.Providers {
		add(fmt.Sprintf("providers[%d].eab_secret (%s)", i, p.Name), p.EABSecretName)
	}
	add("ldap.bind_password_secret", cfg.LDAP.BindPasswordSecret)
	return refs
}

func reservedSecret(name string) bool {
	return strings.HasPrefix(name, core.SecretProviderAccountKeyPrefix) || strings.HasPrefix(name, core.SecretProviderAccountURLPrefix)
}

func (h *Handler) secretsPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	names, err := h.Secrets.List(r.Context())
	if err != nil {
		h.serverError(w, r, cur, "list secrets", err)
		return
	}
	d := &secretsData{Names: names, Refs: secretRefs(h.Config.Current(), names), Reserved: map[string]bool{}}
	for _, ref := range d.Refs {
		if !ref.Exists {
			d.Missing++
		}
	}
	for _, n := range names {
		d.Reserved[n] = reservedSecret(n)
	}
	h.render(w, http.StatusOK, "admin_secrets", h.newPage(w, r, cur, "Secrets", "admin-secrets", d))
}

func (h *Handler) secretSet(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	back := base + "/admin/secrets"
	if !limitForm(w, r, maxSecret+maxForm) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	value := strings.TrimRight(r.PostFormValue("value"), "\r\n")
	switch {
	case !secretNameRe.MatchString(name):
		h.redirect(w, r, back, "error", "Secret names use lower-case letters, digits, '.', '_' and '-' and start with a letter or digit.")
	case reservedSecret(name):
		h.redirect(w, r, back, "error", "Names starting with "+core.SecretProviderAccountKeyPrefix+" or "+core.SecretProviderAccountURLPrefix+" belong to the broker and cannot be set here.")
	case value == "":
		h.redirect(w, r, back, "error", "The secret value is empty.")
	case len(value) > maxSecret:
		h.redirect(w, r, back, "error", "The secret value is too large.")
	default:
		if err := h.Secrets.Put(r.Context(), name, []byte(value)); err != nil {
			h.serverError(w, r, cur, "store secret", err)
			return
		}
		h.record(r, cur, core.AuditConfigChange, "set secret "+name, 0)
		h.redirect(w, r, back, "ok", "Secret "+name+" saved. Its value is never shown again.")
	}
}

func (h *Handler) secretDelete(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	back := base + "/admin/secrets"
	if !limitForm(w, r, maxForm) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !secretNameRe.MatchString(name) || reservedSecret(name) {
		h.redirect(w, r, back, "error", "That secret cannot be deleted here.")
		return
	}
	if err := h.Secrets.Delete(r.Context(), name); err != nil {
		h.serverError(w, r, cur, "delete secret", err)
		return
	}
	h.record(r, cur, core.AuditConfigChange, "deleted secret "+name, 0)
	msg, kind := "Secret "+name+" deleted.", "ok"
	for _, ref := range secretRefs(h.Config.Current(), nil) {
		if ref.Name == name {
			msg += " The active configuration still refers to it (" + ref.Where + ")."
			kind = "warn"
		}
	}
	h.redirect(w, r, back, kind, msg)
}
