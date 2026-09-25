package inventory

import _ "embed"

// ExampleYAML is written by a tool's `init` and printed by its `schema --example`.
//
//go:embed embed/example.yaml
var ExampleYAML string

// ReferenceYAML documents every field; printed by a tool's `schema`.
//
//go:embed embed/reference.yaml
var ReferenceYAML string

// SchemaJSON is a JSON Schema for infra.yaml; printed by a tool's `schema --json`.
//
//go:embed embed/schema.json
var SchemaJSON string
