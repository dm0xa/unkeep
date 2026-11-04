package frontend

import "embed"

// Dist contains the built single-page app. It is embedded into the Go binary;
// no frontend runtime or static file directory is needed in production.
//
//go:embed dist
var Dist embed.FS
