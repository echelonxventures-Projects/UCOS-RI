module ucos.dev/ri/eventing

go 1.25

require (
	github.com/jackc/pgx/v5 v5.7.2
	ucos.dev/ri/authn v0.0.0
	ucos.dev/ri/contextruntime v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace (
	ucos.dev/ri/authn => ../../../platform/authn/go
	ucos.dev/ri/contextruntime => ../../../platform/context-runtime/go
)
