// Package config owns everything the broker reads at start-up or reloads at
// run time: the process environment (Env), the YAML model of a configuration
// generation (Parse, Marshal, Validate), the generation store under
// <data>/config (Store, which implements core.ConfigSource and
// core.ConfigAdmin) and the file-backed secret store under <data>/secrets
// (FileSecrets, which implements core.SecretStore).
//
// Configuration YAML never contains secret values, only the names of secrets
// held in the secret store. Validation always reports every problem at once,
// each with a field path, so a UI can show them next to the fields.
package config
